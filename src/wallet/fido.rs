//! FIDO2 hmac-secret on one USB HID authenticator, and a software stand-in.
//!
//! Enrollment is `authenticatorMakeCredential` with the `hmac-secret`
//! extension, a non-discoverable credential, and a PIN so the output is the
//! UV secret. Unlock is `authenticatorGetAssertion` with that extension.
//! The 32-byte HMAC is the key-encryption key. Nothing here sends a
//! vendor command, a PIV APDU, or `authenticatorReset`.
//!
//! The relying party id is a stable name. CTAP hashes it. It is not fetched.
//! Touch cannot be turned off. A PIN is sent only after exactly one
//! authenticator is connected, because two devices can have different PINs
//! and different retry counters.

use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use super::key_store::KeyStoreError;

const RP_ID: &str = "oid4vc-wallet";

/// A credential this wallet just created, including the HMAC it will seal with.
pub(super) struct Enrollment {
    pub id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub salt: [u8; 32],
    pub kek: [u8; 32],
    pub label: String,
}

impl Drop for Enrollment {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

/// What a security key (or a test double) can do. PIV is the other
/// implementation, so the same two-key logic serves both applications.
pub(super) trait Fido {
    /// The client-side PIN rule, checked before any device call.
    fn check_pin(&self, pin: &str) -> Result<(), KeyStoreError>;
    fn device_count(&mut self) -> Result<usize, KeyStoreError>;
    fn enroll(&mut self, pin: &str) -> Result<Enrollment, KeyStoreError>;
    fn hmac(
        &mut self,
        id: &[u8],
        public_key: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<[u8; 32], KeyStoreError>;
    /// Which of `ids` the single connected authenticator holds. No PIN.
    fn holds(&mut self, ids: &[Vec<u8>]) -> Result<Option<Vec<u8>>, KeyStoreError>;
}

/// CTAP2 over USB HID. `ctap-fido2` speaks the standard messages only.
pub(super) struct HardwareFido;

impl Fido for HardwareFido {
    fn check_pin(&self, pin: &str) -> Result<(), KeyStoreError> {
        check_fido_pin(pin)
    }

    fn device_count(&mut self) -> Result<usize, KeyStoreError> {
        Ok(listed()?.len())
    }

    fn enroll(&mut self, pin: &str) -> Result<Enrollment, KeyStoreError> {
        let (info, mut auth) = open_one()?;
        prepare(&mut auth)?;
        let cred = auth
            .make_credential(RP_ID, &random_hash(), &make_options(pin))
            .map_err(|err| map_ctap(Some(&mut auth), err))?;
        let public_key = cred.public_key.as_cose_bytes().to_vec();
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let kek = hmac_on(&mut auth, &cred.id, &cred.public_key, &salt, pin)?;
        let label = display_label(info.product_string.as_deref().unwrap_or(""), &cred.id);
        Ok(Enrollment {
            id: cred.id,
            public_key,
            salt,
            kek,
            label,
        })
    }

    fn hmac(
        &mut self,
        id: &[u8],
        public_key: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<[u8; 32], KeyStoreError> {
        let (_info, mut auth) = open_one()?;
        prepare(&mut auth)?;
        let key = ctap_fido2::cose::CredentialPublicKey::from_cose_bytes(public_key.to_vec())
            .map_err(|err| map_ctap(None, err))?;
        hmac_on(&mut auth, id, &key, salt, pin)
    }

    fn holds(&mut self, ids: &[Vec<u8>]) -> Result<Option<Vec<u8>>, KeyStoreError> {
        if ids.is_empty() {
            return Ok(None);
        }
        let (_info, mut auth) = open_one()?;
        // One id per probe: a YubiKey answers a credential id minted by
        // another authenticator with InvalidCredential instead of
        // NoCredentials, and one foreign id would hide its own in a list.
        for id in ids {
            let refs = [id.as_slice()];
            // A silent probe does not touch and does not use the PIN.
            // Firmware that rejects up=false falls back to one touch, still
            // without a PIN.
            let found = match auth.probe_credential(RP_ID, &random_hash(), &refs) {
                Err(err) if is_foreign(&err) => None,
                Err(ctap_fido2::error::Error::Ctap(_)) => {
                    match auth.probe_credential_with_touch(RP_ID, &random_hash(), &refs) {
                        Err(err) if is_foreign(&err) => None,
                        Err(err) => return Err(map_ctap(Some(&mut auth), err)),
                        Ok(found) => found,
                    }
                }
                Err(err) => return Err(map_ctap(None, err)),
                Ok(found) => found,
            };
            if found.is_some() {
                return Ok(Some(id.clone()));
            }
        }
        Ok(None)
    }
}

fn check_fido_pin(pin: &str) -> Result<(), KeyStoreError> {
    // FIDO counts UTF-8 bytes. The device enforces its own minimum, which
    // defaults to 4. Letters are allowed. 63 is the CTAP maximum.
    let len = pin.len();
    if len < 4 {
        return Err(plain("wallet.fido.pin_short"));
    }
    if len > 63 {
        return Err(plain("wallet.fido.pin_long"));
    }
    Ok(())
}

/// `CTAP2_ERR_INVALID_CREDENTIAL` (0x22). The crate has no named variant.
fn is_foreign(err: &ctap_fido2::error::Error) -> bool {
    matches!(
        err,
        ctap_fido2::error::Error::Ctap(ctap_fido2::error::CtapStatus::Other(0x22))
    )
}

fn listed() -> Result<Vec<ctap_fido2::device::DeviceInfo>, KeyStoreError> {
    let devices = ctap_fido2::device::list_devices().map_err(|err| map_ctap(None, err))?;
    let mut unique = Vec::new();
    for device in devices {
        if unique
            .iter()
            .any(|seen: &ctap_fido2::device::DeviceInfo| seen.path == device.path)
        {
            continue;
        }
        unique.push(device);
    }
    Ok(unique)
}

fn open_one() -> Result<
    (
        ctap_fido2::device::DeviceInfo,
        ctap_fido2::cmd::Authenticator,
    ),
    KeyStoreError,
> {
    let mut devices = listed()?;
    let info = match devices.len() {
        0 => return Err(plain("wallet.fido.none")),
        1 => devices.remove(0),
        _ => return Err(plain("wallet.fido.many")),
    };
    let auth = ctap_fido2::cmd::Authenticator::open(&info).map_err(|err| map_ctap(None, err))?;
    Ok((info, auth))
}

fn prepare(auth: &mut ctap_fido2::cmd::Authenticator) -> Result<(), KeyStoreError> {
    let info = auth.info().map_err(|err| map_ctap(None, err))?;
    let hmac = info.hmac_secret();
    let pin_set = info.client_pin_set();
    // PIN protocol v2 is not implemented by the CTAP crate. A v2-only
    // authenticator would time out on a v1 exchange, so refuse it here.
    let v1 = info.supports_pin_protocol_v1();
    if !hmac {
        return Err(plain("wallet.fido.no_extension"));
    }
    if !pin_set {
        return Err(plain("wallet.fido.pin_not_set"));
    }
    if !v1 {
        return Err(plain("wallet.fido.pin_protocol"));
    }
    Ok(())
}

fn make_options(pin: &str) -> ctap_fido2::cmd::MakeCredentialOptions<'_> {
    // Some(pin) is what asks for user verification. None would create a
    // different hmac-secret, and that output could not open this wrap.
    ctap_fido2::cmd::MakeCredentialOptions {
        pin: Some(pin),
        resident_key: false,
        cred_protect: None,
        ..Default::default()
    }
}

fn hmac_on(
    auth: &mut ctap_fido2::cmd::Authenticator,
    id: &[u8],
    public_key: &ctap_fido2::cose::CredentialPublicKey,
    salt: &[u8; 32],
    pin: &str,
) -> Result<[u8; 32], KeyStoreError> {
    let hash = random_hash();
    let response = auth
        .get_hmac_secret(&ctap_fido2::cmd::get_assertion::HmacSecretRequest {
            rp_id: RP_ID,
            client_data_hash: &hash,
            cred_id: id,
            salt,
            salt2: None,
            pin: Some(pin),
            public_key: Some(public_key),
            request_cred_blob: false,
        })
        .map_err(|err| map_ctap(Some(auth), err))?;
    Ok(response.secret.0)
}

fn random_hash() -> [u8; 32] {
    let mut hash = [0u8; 32];
    OsRng.fill_bytes(&mut hash);
    hash
}

fn display_label(product: &str, id: &[u8]) -> String {
    let mut name: String = product
        .chars()
        .filter(|ch| !ch.is_control())
        .take(48)
        .collect();
    name = name.trim().to_string();
    if name.is_empty() {
        name = "Security key".to_string();
    }
    format!("{name} {}", fingerprint(id))
}

pub(super) fn fingerprint(id: &[u8]) -> String {
    use std::fmt::Write as _;
    id.iter().take(4).fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn map_ctap(
    auth: Option<&mut ctap_fido2::cmd::Authenticator>,
    err: ctap_fido2::error::Error,
) -> KeyStoreError {
    use ctap_fido2::error::CtapStatus;
    match err {
        ctap_fido2::error::Error::Ctap(CtapStatus::PinInvalid) => pin_invalid(auth),
        ctap_fido2::error::Error::Ctap(CtapStatus::PinBlocked | CtapStatus::PinAuthBlocked) => {
            plain("wallet.fido.pin_blocked")
        }
        ctap_fido2::error::Error::Ctap(CtapStatus::PinNotSet) => plain("wallet.fido.pin_not_set"),
        ctap_fido2::error::Error::Ctap(CtapStatus::PinPolicyViolation) => {
            plain("wallet.fido.pin_policy")
        }
        ctap_fido2::error::Error::Ctap(CtapStatus::UserActionTimeout) => {
            plain("wallet.fido.timeout")
        }
        ctap_fido2::error::Error::Ctap(
            CtapStatus::OperationDenied | CtapStatus::KeepaliveCancel,
        ) => plain("wallet.fido.denied"),
        ctap_fido2::error::Error::Ctap(CtapStatus::NoCredentials) => {
            plain("wallet.fido.not_enrolled")
        }
        ctap_fido2::error::Error::Ctap(CtapStatus::ChannelBusy)
        | ctap_fido2::error::Error::Hid(_) => plain("wallet.fido.hid"),
        ctap_fido2::error::Error::MissingExtension(_) => plain("wallet.fido.no_extension"),
        other => plain_args("wallet.fido.device", &[("message", &other.to_string())]),
    }
}

fn pin_invalid(auth: Option<&mut ctap_fido2::cmd::Authenticator>) -> KeyStoreError {
    let Some(auth) = auth else {
        return plain("wallet.fido.wrong_pin_plain");
    };
    match auth.pin_retries() {
        Ok(tries) => plain_args("wallet.fido.wrong_pin", &[("tries", &tries.to_string())]),
        Err(_) => plain("wallet.fido.wrong_pin_plain"),
    }
}

fn plain(key: &str) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t(key))
}

fn plain_args(key: &str, args: &[(&str, &str)]) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t_args(key, args))
}

/// In-memory credentials. Tests never open `/dev/hidraw`.
#[cfg(test)]
pub(super) struct SoftwareFido {
    connected: Vec<u32>,
    devices: std::collections::HashMap<u32, SoftDevice>,
    next_id: u64,
}

#[cfg(test)]
struct SoftDevice {
    creds: Vec<SoftCred>,
}

#[cfg(test)]
struct SoftCred {
    id: Vec<u8>,
    pin: String,
    secret: [u8; 32],
}

#[cfg(test)]
impl SoftwareFido {
    pub(super) fn new() -> Self {
        Self {
            connected: Vec::new(),
            devices: std::collections::HashMap::new(),
            next_id: 0,
        }
    }

    pub(super) fn set_connected(&mut self, devices: &[u32]) {
        self.connected = devices.to_vec();
    }

    pub(super) fn credential_count(&self, device: u32) -> usize {
        self.devices
            .get(&device)
            .map_or(0, |device| device.creds.len())
    }

    pub(super) fn has_credential(&self, device: u32, id: &[u8]) -> bool {
        self.devices
            .get(&device)
            .is_some_and(|device| device.creds.iter().any(|cred| cred.id == id))
    }
}

#[cfg(test)]
impl Fido for SoftwareFido {
    fn check_pin(&self, pin: &str) -> Result<(), KeyStoreError> {
        check_fido_pin(pin)
    }

    fn device_count(&mut self) -> Result<usize, KeyStoreError> {
        Ok(self.connected.len())
    }

    fn enroll(&mut self, pin: &str) -> Result<Enrollment, KeyStoreError> {
        let device_id = self.only()?;
        self.next_id += 1;
        let id = self.next_id.to_be_bytes().to_vec();
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let kek = mix(&secret, &salt);
        let public_key = id.clone();
        let device = self
            .devices
            .entry(device_id)
            .or_insert_with(|| SoftDevice { creds: Vec::new() });
        device.creds.push(SoftCred {
            id: id.clone(),
            pin: pin.to_string(),
            secret,
        });
        Ok(Enrollment {
            label: display_label("Security key", &id),
            id,
            public_key,
            salt,
            kek,
        })
    }

    fn hmac(
        &mut self,
        id: &[u8],
        _public_key: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<[u8; 32], KeyStoreError> {
        let device_id = self.only()?;
        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| plain("wallet.fido.unwrap"))?;
        let cred = device
            .creds
            .iter()
            .find(|cred| cred.id == id)
            .ok_or_else(|| plain("wallet.fido.unwrap"))?;
        if cred.pin != pin {
            return Err(plain("wallet.fido.wrong_pin_plain"));
        }
        Ok(mix(&cred.secret, salt))
    }

    fn holds(&mut self, ids: &[Vec<u8>]) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let device_id = self.only()?;
        let Some(device) = self.devices.get(&device_id) else {
            return Ok(None);
        };
        Ok(ids
            .iter()
            .find(|id| device.creds.iter().any(|cred| &cred.id == *id))
            .cloned())
    }
}

#[cfg(test)]
impl SoftwareFido {
    fn only(&self) -> Result<u32, KeyStoreError> {
        match self.connected.as_slice() {
            [] => Err(plain("wallet.fido.none")),
            [id] => Ok(*id),
            _ => Err(plain("wallet.fido.many")),
        }
    }
}

/// Stable test output. Not the authenticator's HMAC. The production key is
/// the 32 bytes `get_hmac_secret` returns.
#[cfg(test)]
fn mix(secret: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"oid4vc-wallet test kek v1");
    hasher.update(secret);
    hasher.update(salt);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
