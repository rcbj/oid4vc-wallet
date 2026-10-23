//! PIV slot 82 on a YubiKey, as the other device behind [`Fido`].
//!
//! FIDO2 hmac-secret is the default because far more authenticators ship
//! the FIDO2 application than PIV. This path is for a YubiKey whose FIDO2
//! application is unavailable or reserved, and needs pcscd.
//!
//! Retired slot `0x82` is unused by the PIV authentication, signature, and
//! key-management slots, so enrolling does not replace a key the person
//! already uses for something else. The PIN policy is "always": the card
//! demands the PIN on the private-key operation itself. Touch is not
//! required, because the PIN is the user verification this wallet asks for.
//! A slot that already holds a key is left alone.
//!
//! The key-encryption key has to come out the same for the same stored salt,
//! like hmac-secret, so the protection logic and file stay shared. The card
//! runs ECDH between its slot key and a point hashed from the salt. Nobody
//! knows that point's discrete log, so only the card can compute the shared
//! X. HKDF turns X into the 32-byte KEK.

use p256::elliptic_curve::ecdh::SharedSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use yubikey::piv::{decrypt_data, generate, metadata, AlgorithmId, RetiredSlotId, SlotId};
use yubikey::reader::Context;
use yubikey::{MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey};

use super::fido::{with_detail, Enrollment, Fido};
use super::key_store::KeyStoreError;

const SLOT: SlotId = SlotId::Retired(RetiredSlotId::R1);
const POINT_DOMAIN: &[u8] = b"oid4vc-wallet piv salt point v1";
const KEK_SALT: &[u8] = b"oid4vc-wallet piv kek v1";
const POINT_LEN: usize = 65;

/// The PC/SC YubiKey.
pub(super) struct HardwarePiv;

impl Fido for HardwarePiv {
    fn check_pin(&self, pin: &str) -> Result<(), KeyStoreError> {
        check_piv_pin(pin)
    }

    fn device_count(&mut self) -> Result<usize, KeyStoreError> {
        Ok(serials()?.len())
    }

    fn enroll(&mut self, pin: &str) -> Result<Enrollment, KeyStoreError> {
        let serial = only_serial()?;
        let mut yk = open_serial(serial)?;
        yk.verify_pin(pin.as_bytes()).map_err(map_yubi)?;
        yk.authenticate(MgmKey::default()).map_err(map_mgmt)?;
        if slot_point(&mut yk)?.is_some() || slot_has_certificate(&mut yk)? {
            return Err(plain("wallet.piv.slot_busy"));
        }
        let spki = generate(
            &mut yk,
            SLOT,
            AlgorithmId::EccP256,
            PinPolicy::Always,
            TouchPolicy::Never,
        )
        .map_err(map_mgmt)?;
        let point = point_of(&spki).ok_or_else(|| plain("wallet.fido.unwrap"))?;
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let kek = kek_on(&mut yk, pin, &salt)?;
        Ok(Enrollment {
            id: point.to_vec(),
            public_key: point.to_vec(),
            salt,
            kek,
            label: format!("YubiKey {serial} PIV"),
        })
    }

    fn hmac(
        &mut self,
        _id: &[u8],
        _public_key: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<[u8; 32], KeyStoreError> {
        let mut yk = open_serial(only_serial()?)?;
        kek_on(&mut yk, pin, salt)
    }

    fn holds(&mut self, ids: &[Vec<u8>]) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let mut yk = open_serial(only_serial()?)?;
        let Some(point) = slot_point(&mut yk)? else {
            return Ok(None);
        };
        Ok(ids.iter().find(|id| id.as_slice() == point).cloned())
    }
}

/// PIV PINs are six to eight characters. This wallet keeps the YubiKey
/// default of digits, as the earlier PIV wrap did.
fn check_piv_pin(pin: &str) -> Result<(), KeyStoreError> {
    if !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(plain("wallet.piv.pin_digits"));
    }
    if pin.len() < 6 {
        return Err(plain("wallet.piv.pin_short"));
    }
    if pin.len() > 8 {
        return Err(plain("wallet.piv.pin_long"));
    }
    Ok(())
}

fn serials() -> Result<Vec<u32>, KeyStoreError> {
    let mut context = Context::open().map_err(map_yubi)?;
    let mut serials = Vec::new();
    let mut refused = Vec::new();
    for reader in context.iter().map_err(map_yubi)? {
        let name = reader.name().to_string();
        match YubiKey::try_from(&reader) {
            Ok(yk) => {
                let serial = u32::from(yk.serial());
                if serial == 0 {
                    refused.push(plain_args(
                        "wallet.piv.open_failed",
                        &[("reader", &name), ("detail", "serial 0")],
                    ));
                } else if !serials.contains(&serial) {
                    serials.push(serial);
                }
            }
            Err(err) => refused.push(refusal(&name, err)),
        }
    }
    // A reader whose key the library refused must not read as "no key".
    if serials.is_empty() {
        if let Some(first) = refused.into_iter().next() {
            return Err(first);
        }
    }
    Ok(serials)
}

fn refusal(reader: &str, err: yubikey::Error) -> KeyStoreError {
    if matches!(err, yubikey::Error::NotSupported) {
        if let Some(version) = piv_version(reader) {
            return with_detail(
                plain_args(
                    "wallet.piv.unsupported_version",
                    &[("reader", reader), ("version", &version)],
                ),
                &detail(err),
            );
        }
    }
    plain_args(
        "wallet.piv.open_failed",
        &[("reader", reader), ("detail", &detail(err))],
    )
}

/// The yubikey crate reads a serial only from PIV firmware 4 and 5, and
/// returns `NotSupported` for any other version without saying which. SELECT
/// and GET VERSION are read-only and need no PIN, so ask the card directly.
fn piv_version(reader: &str) -> Option<String> {
    let context = pcsc::Context::establish(pcsc::Scope::User).ok()?;
    let name = std::ffi::CString::new(reader).ok()?;
    let card = context
        .connect(&name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
        .ok()?;
    let mut buffer = [0u8; 258];
    let select = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    if !card
        .transmit(&select, &mut buffer)
        .ok()?
        .ends_with(&[0x90, 0x00])
    {
        return None;
    }
    let reply = card
        .transmit(&[0x00, 0xFD, 0x00, 0x00, 0x00], &mut buffer)
        .ok()?;
    if reply.len() >= 5 && reply.ends_with(&[0x90, 0x00]) {
        Some(format!("{}.{}.{}", reply[0], reply[1], reply[2]))
    } else {
        None
    }
}

/// The Yubico C library's error name, the crate's sentence, and the variant
/// with its fields (the PC/SC code, the PIN tries), for looking the failure up.
fn detail(err: yubikey::Error) -> String {
    format!("{}: {err} ({err:?})", err.name().unwrap_or("YKPIV"))
}

fn only_serial() -> Result<u32, KeyStoreError> {
    match serials()?.as_slice() {
        [] => Err(plain("wallet.fido.none")),
        [serial] => Ok(*serial),
        _ => Err(plain("wallet.fido.many")),
    }
}

fn open_serial(serial: u32) -> Result<YubiKey, KeyStoreError> {
    YubiKey::open_by_serial(Serial::from(serial)).map_err(map_yubi)
}

fn kek_on(yk: &mut YubiKey, pin: &str, salt: &[u8; 32]) -> Result<[u8; 32], KeyStoreError> {
    let point = salt_point(salt)?;
    // PinPolicy::Always is satisfied only when the PIN and the decipher
    // are the next two commands. Metadata in between would ask again.
    yk.verify_pin(pin.as_bytes()).map_err(map_yubi)?;
    let shared = decrypt_data(yk, &point, AlgorithmId::EccP256, SLOT).map_err(|err| {
        if matches!(err, yubikey::Error::AuthenticationError) {
            with_detail(plain("wallet.piv.pin_again"), &detail(err))
        } else {
            map_yubi(err)
        }
    })?;
    derive_kek(&shared_x_from_card(&shared)?, salt)
}

/// The slot-82 public point, or `None` when the slot is empty.
fn slot_point(yk: &mut YubiKey) -> Result<Option<[u8; POINT_LEN]>, KeyStoreError> {
    match metadata(yk, SLOT) {
        Ok(meta) => Ok(meta.public.as_ref().and_then(point_of)),
        // Some firmware answers an empty slot with a generic error.
        Err(yubikey::Error::GenericError) => Ok(None),
        Err(err) => Err(map_yubi(err)),
    }
}

fn slot_has_certificate(yk: &mut YubiKey) -> Result<bool, KeyStoreError> {
    let keys = yk.piv_keys().map_err(map_yubi)?;
    Ok(keys.into_iter().any(|key| key.slot() == SLOT))
}

fn point_of(spki: &p256::pkcs8::spki::SubjectPublicKeyInfoOwned) -> Option<[u8; POINT_LEN]> {
    let public = PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes()).ok()?;
    Some(uncompressed_point(&public))
}

/// A point on P-256 from the salt, by try-and-increment. Its discrete log is
/// unknown, so knowing the salt does not give the shared secret.
fn salt_point(salt: &[u8; 32]) -> Result<[u8; POINT_LEN], KeyStoreError> {
    for counter in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(POINT_DOMAIN);
        hasher.update(salt);
        hasher.update([counter]);
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&hasher.finalize());
        if let Ok(public) = PublicKey::from_sec1_bytes(&compressed) {
            return Ok(uncompressed_point(&public));
        }
    }
    Err(plain("wallet.fido.unwrap"))
}

fn derive_kek(shared_x: &[u8; 32], salt: &[u8; 32]) -> Result<[u8; 32], KeyStoreError> {
    let mut field = p256::FieldBytes::default();
    field.copy_from_slice(shared_x);
    let shared = SharedSecret::<p256::NistP256>::from(field);
    let mut okm = [0u8; 32];
    shared
        .extract::<Sha256>(Some(KEK_SALT))
        .expand(salt, &mut okm)
        .map_err(|_| plain("wallet.fido.unwrap"))?;
    Ok(okm)
}

/// The card's decipher of a P-256 point is the shared X, a raw point, or a short integer.
fn shared_x_from_card(bytes: &[u8]) -> Result<[u8; 32], KeyStoreError> {
    let mut x = [0u8; 32];
    if bytes.len() == 32 {
        x.copy_from_slice(bytes);
    } else if bytes.len() == POINT_LEN && bytes[0] == 0x04 {
        x.copy_from_slice(&bytes[1..33]);
    } else if (1..32).contains(&bytes.len()) {
        x[32 - bytes.len()..].copy_from_slice(bytes);
    } else {
        return Err(plain("wallet.fido.unwrap"));
    }
    Ok(x)
}

fn uncompressed_point(public: &PublicKey) -> [u8; POINT_LEN] {
    let encoded = public.to_encoded_point(false);
    let mut point = [0u8; POINT_LEN];
    point.copy_from_slice(encoded.as_bytes());
    point
}

fn map_mgmt(err: yubikey::Error) -> KeyStoreError {
    if matches!(err, yubikey::Error::AuthenticationError) {
        with_detail(plain("wallet.piv.mgmt"), &detail(err))
    } else {
        map_yubi(err)
    }
}

fn map_yubi(err: yubikey::Error) -> KeyStoreError {
    let mapped = match err {
        yubikey::Error::PcscError { .. } => plain("wallet.piv.pcsc"),
        yubikey::Error::WrongPin { tries } => {
            plain_args("wallet.piv.wrong_pin", &[("tries", &tries.to_string())])
        }
        yubikey::Error::PinLocked => plain("wallet.piv.pin_blocked"),
        yubikey::Error::NotSupported => plain("wallet.piv.firmware"),
        other => return plain_args("wallet.piv.device", &[("message", &detail(other))]),
    };
    with_detail(mapped, &detail(err))
}

fn plain(key: &str) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t(key))
}

fn plain_args(key: &str, args: &[(&str, &str)]) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t_args(key, args))
}

/// In-memory slot-82 keys that run the same ECDH and HKDF as the card path.
/// Tests never open a reader.
#[cfg(test)]
pub(super) struct SoftwarePiv {
    connected: Vec<u32>,
    slots: std::collections::HashMap<u32, (String, p256::SecretKey)>,
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

    fn only(&self) -> Result<u32, KeyStoreError> {
        match self.connected.as_slice() {
            [] => Err(plain("wallet.fido.none")),
            [serial] => Ok(*serial),
            _ => Err(plain("wallet.fido.many")),
        }
    }
}

#[cfg(test)]
impl Fido for SoftwarePiv {
    fn check_pin(&self, pin: &str) -> Result<(), KeyStoreError> {
        check_piv_pin(pin)
    }

    fn device_count(&mut self) -> Result<usize, KeyStoreError> {
        Ok(self.connected.len())
    }

    fn enroll(&mut self, pin: &str) -> Result<Enrollment, KeyStoreError> {
        let serial = self.only()?;
        if self.slots.contains_key(&serial) {
            return Err(plain("wallet.piv.slot_busy"));
        }
        let secret = p256::SecretKey::random(&mut OsRng);
        let point = uncompressed_point(&secret.public_key());
        self.slots.insert(serial, (pin.to_string(), secret));
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let kek = self.hmac(&point, &point, &salt, pin)?;
        Ok(Enrollment {
            id: point.to_vec(),
            public_key: point.to_vec(),
            salt,
            kek,
            label: format!("YubiKey {serial} PIV"),
        })
    }

    fn hmac(
        &mut self,
        _id: &[u8],
        _public_key: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<[u8; 32], KeyStoreError> {
        let serial = self.only()?;
        let (stored_pin, secret) = self
            .slots
            .get(&serial)
            .ok_or_else(|| plain("wallet.fido.unwrap"))?;
        if stored_pin != pin {
            return Err(plain("wallet.piv.wrong_pin_plain"));
        }
        let point = PublicKey::from_sec1_bytes(&salt_point(salt)?)
            .map_err(|_| plain("wallet.fido.unwrap"))?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), *point.as_affine());
        let mut x = [0u8; 32];
        x.copy_from_slice(shared.raw_secret_bytes());
        derive_kek(&x, salt)
    }

    fn holds(&mut self, ids: &[Vec<u8>]) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let serial = self.only()?;
        let Some((_, secret)) = self.slots.get(&serial) else {
            return Ok(None);
        };
        let point = uncompressed_point(&secret.public_key());
        Ok(ids.iter().find(|id| id.as_slice() == point).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_salt_point_is_on_the_curve_and_depends_on_the_salt() {
        let one = salt_point(&[1; 32]).unwrap();
        assert_eq!(one, salt_point(&[1; 32]).unwrap());
        assert_ne!(one, salt_point(&[2; 32]).unwrap());
        assert!(PublicKey::from_sec1_bytes(&one).is_ok());
    }

    #[test]
    fn the_card_coordinate_may_be_a_point_or_a_short_integer() {
        let mut x = [0u8; 32];
        x[31] = 0x2a;
        assert_eq!(shared_x_from_card(&x).unwrap(), x);
        let mut point = vec![0x04];
        point.extend_from_slice(&x);
        point.extend_from_slice(&[0u8; 32]);
        assert_eq!(shared_x_from_card(&point).unwrap(), x);
        assert_eq!(shared_x_from_card(&[0x2a]).unwrap()[31], 0x2a);
        assert!(shared_x_from_card(&[]).is_err());
        assert!(shared_x_from_card(&[0u8; 40]).is_err());
    }

    #[test]
    fn a_piv_pin_is_six_to_eight_digits() {
        assert!(check_piv_pin("123456").is_ok());
        assert!(check_piv_pin("12345678").is_ok());
        assert!(check_piv_pin("12345").is_err());
        assert!(check_piv_pin("123456789").is_err());
        assert!(check_piv_pin("12345a").is_err());
    }
}
