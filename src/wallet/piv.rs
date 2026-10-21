//! PIV slot 82 on a YubiKey, and a software stand-in for tests.
//!
//! Retired slot `0x82` is unused by the PIV authentication, signature, and
//! key-management slots, so enrolling does not replace a key the person
//! already uses for something else. The PIN policy is "always": the card
//! demands the PIN on the private-key operation itself. Touch is not
//! required, because the PIN is the user verification this wallet asks for.
//!
//! A slot that already holds a key is left alone. An empty slot, including
//! one whose metadata command answers with a generic error and whose
//! certificate list is empty, gets a new P-256 key.

use p256::PublicKey;
use yubikey::piv::{decrypt_data, generate, metadata, AlgorithmId, RetiredSlotId, SlotId};
use yubikey::reader::Context;
use yubikey::{MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey};

use super::kek::uncompressed_point;
use super::key_store::KeyStoreError;

const SLOT: SlotId = SlotId::Retired(RetiredSlotId::R1);

/// What a YubiKey (or the test double) can do for this wallet.
pub(super) trait Piv {
    fn connected(&mut self) -> Result<Vec<u32>, KeyStoreError>;
    fn enroll(&mut self, serial: u32, pin: &str) -> Result<[u8; 65], PivError>;
    fn shared_secret(
        &mut self,
        serial: u32,
        pin: &str,
        ephemeral: &[u8; 65],
    ) -> Result<[u8; 32], KeyStoreError>;
}

/// `Busy` means slot 82 already has a key. `Some` is that key's point when
/// the card told us what it is.
pub(super) enum PivError {
    Store(KeyStoreError),
    Busy(Option<[u8; 65]>),
}

/// The PC/SC YubiKey.
pub(super) struct HardwarePiv;

impl Piv for HardwarePiv {
    fn connected(&mut self) -> Result<Vec<u32>, KeyStoreError> {
        let mut context = Context::open().map_err(map_yubi)?;
        let mut serials = Vec::new();
        for reader in context.iter().map_err(map_yubi)? {
            let Ok(yk) = YubiKey::try_from(&reader) else {
                continue;
            };
            let serial = u32::from(yk.serial());
            if serial != 0 && !serials.contains(&serial) {
                serials.push(serial);
            }
        }
        Ok(serials)
    }

    fn enroll(&mut self, serial: u32, pin: &str) -> Result<[u8; 65], PivError> {
        let mut yk = open_serial(serial).map_err(PivError::Store)?;
        yk.verify_pin(pin.as_bytes())
            .map_err(map_pin)
            .map_err(PivError::Store)?;
        yk.authenticate(MgmKey::default())
            .map_err(map_mgmt)
            .map_err(PivError::Store)?;
        match metadata(&mut yk, SLOT) {
            Ok(meta) => {
                if let Some(public) = meta.public {
                    return Err(PivError::Busy(point_of(&public)));
                }
                if slot_has_certificate(&mut yk).map_err(PivError::Store)? {
                    return Err(PivError::Busy(None));
                }
            }
            Err(yubikey::Error::NotSupported) => {
                return Err(PivError::Store(plain("wallet.yubi.firmware")));
            }
            Err(yubikey::Error::GenericError) => match slot_has_certificate(&mut yk) {
                Ok(true) => return Err(PivError::Busy(None)),
                Ok(false) => {}
                Err(err) => return Err(PivError::Store(err)),
            },
            Err(err) => return Err(PivError::Store(map_yubi(err))),
        }
        let spki = generate(
            &mut yk,
            SLOT,
            AlgorithmId::EccP256,
            PinPolicy::Always,
            TouchPolicy::Never,
        )
        .map_err(map_generate)
        .map_err(PivError::Store)?;
        match point_of(&spki) {
            Some(point) => Ok(point),
            None => Err(PivError::Store(plain("wallet.yubi.unwrap"))),
        }
    }

    fn shared_secret(
        &mut self,
        serial: u32,
        pin: &str,
        ephemeral: &[u8; 65],
    ) -> Result<[u8; 32], KeyStoreError> {
        // PinPolicy::Always is satisfied only when the PIN and the decipher
        // are the next two commands. Metadata in between would ask again.
        let mut yk = open_serial(serial)?;
        yk.verify_pin(pin.as_bytes()).map_err(map_pin)?;
        let shared =
            decrypt_data(&mut yk, ephemeral, AlgorithmId::EccP256, SLOT).map_err(|err| {
                if matches!(err, yubikey::Error::AuthenticationError) {
                    plain("wallet.yubi.pin_again")
                } else {
                    map_yubi(err)
                }
            })?;
        super::kek::shared_x_from_card(&shared)
    }
}

fn open_serial(serial: u32) -> Result<YubiKey, KeyStoreError> {
    YubiKey::open_by_serial(Serial::from(serial)).map_err(map_yubi)
}

fn slot_has_certificate(yk: &mut YubiKey) -> Result<bool, KeyStoreError> {
    let keys = yk.piv_keys().map_err(map_yubi)?;
    Ok(keys.into_iter().any(|key| key.slot() == SLOT))
}

fn point_of(spki: &p256::pkcs8::spki::SubjectPublicKeyInfoOwned) -> Option<[u8; 65]> {
    let raw = spki.subject_public_key.raw_bytes();
    let point = if raw.len() == 65 && raw[0] == 0x04 {
        let mut point = [0u8; 65];
        point.copy_from_slice(raw);
        point
    } else {
        let public = PublicKey::from_sec1_bytes(raw).ok()?;
        uncompressed_point(&public)
    };
    PublicKey::from_sec1_bytes(&point).ok()?;
    Some(point)
}

fn map_generate(err: yubikey::Error) -> KeyStoreError {
    if matches!(err, yubikey::Error::AuthenticationError) {
        plain("wallet.yubi.mgmt")
    } else {
        map_yubi(err)
    }
}

fn map_mgmt(err: yubikey::Error) -> KeyStoreError {
    if matches!(err, yubikey::Error::AuthenticationError) {
        plain("wallet.yubi.mgmt")
    } else {
        map_yubi(err)
    }
}

fn map_pin(err: yubikey::Error) -> KeyStoreError {
    match err {
        yubikey::Error::WrongPin { tries } => {
            plain_args("wallet.yubi.wrong_pin", &[("tries", &tries.to_string())])
        }
        yubikey::Error::PinLocked => plain("wallet.yubi.pin_blocked"),
        other => map_yubi(other),
    }
}

fn map_yubi(err: yubikey::Error) -> KeyStoreError {
    match err {
        yubikey::Error::PcscError { .. } => plain("wallet.yubi.pcsc"),
        yubikey::Error::WrongPin { tries } => {
            plain_args("wallet.yubi.wrong_pin", &[("tries", &tries.to_string())])
        }
        yubikey::Error::PinLocked => plain("wallet.yubi.pin_blocked"),
        yubikey::Error::NotSupported => plain("wallet.yubi.firmware"),
        other => plain_args("wallet.yubi.device", &[("message", &other.to_string())]),
    }
}

fn plain(key: &str) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t(key))
}

fn plain_args(key: &str, args: &[(&str, &str)]) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t_args(key, args))
}

/// In-memory P-256 keys. Tests never open a reader or the user's key ring.
#[cfg(test)]
pub(super) struct SoftwarePiv {
    connected: Vec<u32>,
    slots: std::collections::HashMap<u32, SoftSlot>,
}

#[cfg(test)]
struct SoftSlot {
    pin: String,
    secret: Option<p256::SecretKey>,
    foreign: bool,
}

#[cfg(test)]
impl SoftwarePiv {
    pub(super) fn new() -> Self {
        Self {
            connected: Vec::new(),
            slots: std::collections::HashMap::new(),
        }
    }

    pub(super) fn set_connected(&mut self, serials: &[u32]) {
        self.connected = serials.to_vec();
    }

    pub(super) fn reset_slot(&mut self, serial: u32) {
        if let Some(slot) = self.slots.get_mut(&serial) {
            slot.secret = None;
            slot.foreign = false;
        }
    }

    pub(super) fn occupy_foreign(&mut self, serial: u32) {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        self.slots.insert(
            serial,
            SoftSlot {
                pin: String::new(),
                secret: Some(secret),
                foreign: true,
            },
        );
    }

    pub(super) fn has_secret(&self, serial: u32) -> bool {
        self.slots
            .get(&serial)
            .is_some_and(|slot| slot.secret.is_some())
    }
}

#[cfg(test)]
impl Piv for SoftwarePiv {
    fn connected(&mut self) -> Result<Vec<u32>, KeyStoreError> {
        Ok(self.connected.clone())
    }

    fn enroll(&mut self, serial: u32, pin: &str) -> Result<[u8; 65], PivError> {
        let slot = self.slots.entry(serial).or_insert_with(|| SoftSlot {
            pin: String::new(),
            secret: None,
            foreign: false,
        });
        if slot.foreign || slot.secret.is_some() {
            let point = slot
                .secret
                .as_ref()
                .map(|secret| uncompressed_point(&secret.public_key()));
            return Err(PivError::Busy(point));
        }
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let point = uncompressed_point(&secret.public_key());
        slot.secret = Some(secret);
        slot.pin = pin.to_string();
        slot.foreign = false;
        Ok(point)
    }

    fn shared_secret(
        &mut self,
        serial: u32,
        pin: &str,
        ephemeral: &[u8; 65],
    ) -> Result<[u8; 32], KeyStoreError> {
        let slot = self
            .slots
            .get(&serial)
            .ok_or_else(|| plain("wallet.yubi.unwrap"))?;
        if slot.pin != pin {
            return Err(plain("wallet.yubi.wrong_pin_plain"));
        }
        let secret = slot
            .secret
            .as_ref()
            .ok_or_else(|| plain("wallet.yubi.unwrap"))?;
        let public =
            PublicKey::from_sec1_bytes(ephemeral).map_err(|_| plain("wallet.yubi.unwrap"))?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), *public.as_affine());
        let mut x = [0u8; 32];
        x.copy_from_slice(shared.raw_secret_bytes());
        Ok(x)
    }
}
