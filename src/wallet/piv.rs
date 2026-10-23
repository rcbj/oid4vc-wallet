//! PIV slot 82 on a YubiKey, as the other device behind [`Fido`].
//!
//! FIDO2 hmac-secret is the default because far more authenticators ship
//! the FIDO2 application than PIV. This path is for a YubiKey whose FIDO2
//! application is unavailable or reserved, and needs pcscd.
//!
//! The PIV commands are sent here over PC/SC rather than through a PIV
//! library. The `yubikey` crate refuses any PIV firmware other than 4.x and
//! 5.x before sending a command, so a newer YubiKey could not be used at all.
//! Only standard PIV instructions and the YubiKey extensions every 5.x key
//! has (GET SERIAL, GET METADATA) are sent, and nothing is version-gated.
//!
//! Retired slot `0x82` is unused by the PIV authentication, signature, and
//! key-management slots, so enrolling does not replace a key the person
//! already uses for something else. The PIN policy is "always": the card
//! demands the PIN on the private-key operation itself. Touch is not
//! required, because the PIN is the user verification this wallet asks for.
//! A slot that already holds a key or a certificate is left alone.
//!
//! The key-encryption key has to come out the same for the same stored salt,
//! like hmac-secret, so the protection logic and file stay shared. The card
//! runs ECDH between its slot key and a point hashed from the salt. Nobody
//! knows that point's discrete log, so only the card can compute the shared
//! X. HKDF turns X into the 32-byte KEK.
//!
//! Every card failure names the command and its status word, so a refusal
//! can be looked up instead of guessed at.

use p256::elliptic_curve::ecdh::SharedSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::fido::{with_detail, Enrollment, Fido};
use super::key_store::KeyStoreError;

const POINT_DOMAIN: &[u8] = b"oid4vc-wallet piv salt point v1";
const KEK_SALT: &[u8] = b"oid4vc-wallet piv kek v1";
const POINT_LEN: usize = 65;

const PIV_AID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];
const SLOT: u8 = 0x82;
const MGMT_SLOT: u8 = 0x9B;
const ALG_TDES: u8 = 0x03;
const ALG_AES192: u8 = 0x0A;
const ALG_P256: u8 = 0x11;
const PIN_POLICY_ALWAYS: u8 = 0x03;
const TOUCH_POLICY_NEVER: u8 = 0x01;
/// The YubiKey factory management key. Firmware before 5.7 holds it as
/// 3DES and 5.7 and later as AES-192; the bytes are the same.
const DEFAULT_MGMT: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

const SW_OK: u16 = 0x9000;
const SW_SECURITY: u16 = 0x6982;
const SW_PIN_BLOCKED: u16 = 0x6983;
const SW_NOT_FOUND: u16 = 0x6A82;
const SW_NO_DATA: u16 = 0x6A88;
const SW_NO_INS: u16 = 0x6D00;

/// The PC/SC YubiKey.
pub(super) struct HardwarePiv;

impl Fido for HardwarePiv {
    fn check_pin(&self, pin: &str) -> Result<(), KeyStoreError> {
        check_piv_pin(pin)
    }

    fn device_count(&mut self) -> Result<usize, KeyStoreError> {
        Ok(yubikeys()?.len())
    }

    fn enroll(&mut self, pin: &str) -> Result<Enrollment, KeyStoreError> {
        let (serial, mut card) = only_yubikey()?;
        let tx = card.transaction().map_err(map_pcsc)?;
        select(&tx)?;
        verify(&tx, pin)?;
        authenticate(&tx)?;
        if slot_point(&tx)?.is_some() || slot_has_certificate(&tx)? {
            return Err(plain("wallet.piv.slot_busy"));
        }
        let point = generate(&tx)?;
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let kek = kek_on(&tx, pin, &salt)?;
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
        let (_serial, mut card) = only_yubikey()?;
        let tx = card.transaction().map_err(map_pcsc)?;
        select(&tx)?;
        kek_on(&tx, pin, salt)
    }

    fn holds(&mut self, ids: &[Vec<u8>]) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let (_serial, card) = only_yubikey()?;
        select(&card)?;
        let Some(point) = slot_point(&card)? else {
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

/// Every reader whose card answers SELECT PIV and the YubiKey GET SERIAL.
///
/// A reader whose card refused is reported when no YubiKey answered, so a
/// refusal does not read as "no key connected".
fn yubikeys() -> Result<Vec<(u32, pcsc::Card)>, KeyStoreError> {
    let context = pcsc::Context::establish(pcsc::Scope::User).map_err(map_pcsc)?;
    let readers = match context.list_readers_owned() {
        Ok(readers) => readers,
        Err(pcsc::Error::NoReadersAvailable) => Vec::new(),
        Err(err) => return Err(map_pcsc(err)),
    };
    let mut found: Vec<(u32, pcsc::Card)> = Vec::new();
    let mut refused = Vec::new();
    for reader in readers {
        let name = reader.to_string_lossy().into_owned();
        let card = match context.connect(&reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
            Ok(card) => card,
            // An empty card slot is not a refusal.
            Err(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard) => continue,
            Err(err) => {
                refused.push(open_failed(&name, &pcsc_detail(err)));
                continue;
            }
        };
        match select(&card).and_then(|()| serial(&card)) {
            Ok(serial) if !found.iter().any(|(seen, _)| *seen == serial) => {
                found.push((serial, card));
            }
            Ok(_) => {}
            Err(err) => refused.push(open_failed(&name, &err.to_string())),
        }
    }
    if found.is_empty() {
        if let Some(first) = refused.into_iter().next() {
            return Err(first);
        }
    }
    Ok(found)
}

fn only_yubikey() -> Result<(u32, pcsc::Card), KeyStoreError> {
    let mut found = yubikeys()?;
    match found.len() {
        0 => Err(plain("wallet.fido.none")),
        1 => Ok(found.remove(0)),
        _ => Err(plain("wallet.fido.many")),
    }
}

fn open_failed(reader: &str, detail: &str) -> KeyStoreError {
    plain_args(
        "wallet.piv.open_failed",
        &[("reader", reader), ("detail", detail)],
    )
}

fn select(card: &pcsc::Card) -> Result<(), KeyStoreError> {
    let (_, sw) = apdu(card, 0xA4, 0x04, 0x00, &PIV_AID, true)?;
    expect(sw, "SELECT PIV")
}

fn serial(card: &pcsc::Card) -> Result<u32, KeyStoreError> {
    let (body, sw) = apdu(card, 0xF8, 0x00, 0x00, &[], true)?;
    expect(sw, "GET SERIAL")?;
    let bytes: [u8; 4] = body
        .as_slice()
        .try_into()
        .map_err(|_| failed("GET SERIAL", sw))?;
    Ok(u32::from_be_bytes(bytes))
}

fn verify(card: &pcsc::Card, pin: &str) -> Result<(), KeyStoreError> {
    // The PIN reference is padded with 0xFF to eight bytes.
    let mut padded = [0xFFu8; 8];
    padded[..pin.len()].copy_from_slice(pin.as_bytes());
    let result = apdu(card, 0x20, 0x00, 0x80, &padded, false);
    padded.zeroize();
    let (_, sw) = result?;
    match sw {
        SW_OK => Ok(()),
        SW_PIN_BLOCKED => Err(sw_detail(plain("wallet.piv.pin_blocked"), "VERIFY", sw)),
        _ if sw & 0xFFF0 == 0x63C0 => Err(sw_detail(
            plain_args(
                "wallet.piv.wrong_pin",
                &[("tries", &(sw & 0x000F).to_string())],
            ),
            "VERIFY",
            sw,
        )),
        _ => Err(failed("VERIFY", sw)),
    }
}

/// The YubiKey GET METADATA reply for `slot`, or `None` when it is empty.
fn metadata(card: &pcsc::Card, slot: u8) -> Result<Option<Vec<u8>>, KeyStoreError> {
    let (body, sw) = apdu(card, 0xF7, 0x00, slot, &[], true)?;
    match sw {
        SW_OK => Ok(Some(body)),
        SW_NO_DATA => Ok(None),
        SW_NO_INS => Err(sw_detail(plain("wallet.piv.firmware"), "GET METADATA", sw)),
        _ => Err(failed("GET METADATA", sw)),
    }
}

/// The slot-82 public point, or `None` when the slot is empty.
fn slot_point(card: &pcsc::Card) -> Result<Option<[u8; POINT_LEN]>, KeyStoreError> {
    Ok(metadata(card, SLOT)?.and_then(|meta| {
        tlv(&meta, 0x04)
            .and_then(|public| tlv(public, 0x86))
            .and_then(point_of)
    }))
}

fn slot_has_certificate(card: &pcsc::Card) -> Result<bool, KeyStoreError> {
    // Object 5FC10D is the certificate for retired slot 82.
    let (body, sw) = apdu(
        card,
        0xCB,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x0D],
        true,
    )?;
    match sw {
        SW_OK => Ok(!body.is_empty()),
        SW_NOT_FOUND => Ok(false),
        _ => Err(failed("GET DATA 5FC10D", sw)),
    }
}

/// Mutual authentication with the factory management key, which GENERATE
/// needs. The card states the key's algorithm in its metadata; firmware
/// without metadata for slot 9B has 3DES.
fn authenticate(card: &pcsc::Card) -> Result<(), KeyStoreError> {
    let algorithm = metadata(card, MGMT_SLOT)
        .ok()
        .flatten()
        .and_then(|meta| tlv(&meta, 0x01).and_then(|value| value.first().copied()))
        .unwrap_or(ALG_TDES);
    let block = match algorithm {
        ALG_TDES => 8,
        ALG_AES192 => 16,
        other => {
            return Err(with_detail(
                plain("wallet.piv.mgmt"),
                &format!("management key algorithm 0x{other:02X}"),
            ))
        }
    };
    let (reply, sw) = apdu(
        card,
        0x87,
        algorithm,
        MGMT_SLOT,
        &[0x7C, 0x02, 0x80, 0x00],
        true,
    )?;
    expect(sw, "GENERAL AUTHENTICATE 9B")?;
    let mut witness = tlv(&reply, 0x7C)
        .and_then(|dynamic| tlv(dynamic, 0x80))
        .filter(|witness| witness.len() == block)
        .ok_or_else(|| failed("GENERAL AUTHENTICATE 9B", sw))?
        .to_vec();
    mgmt_crypt(algorithm, &mut witness, false)?;
    let mut challenge = vec![0u8; block];
    OsRng.fill_bytes(&mut challenge);
    let block_len = u8::try_from(block).map_err(|_| plain("wallet.piv.mgmt"))?;
    let inner = u8::try_from(2 * (2 + block)).map_err(|_| plain("wallet.piv.mgmt"))?;
    let mut data = vec![0x7C, inner, 0x80, block_len];
    data.extend_from_slice(&witness);
    data.extend_from_slice(&[0x81, block_len]);
    data.extend_from_slice(&challenge);
    let (reply, sw) = apdu(card, 0x87, algorithm, MGMT_SLOT, &data, true)?;
    if sw == SW_SECURITY {
        return Err(sw_detail(
            plain("wallet.piv.mgmt"),
            "GENERAL AUTHENTICATE 9B",
            sw,
        ));
    }
    expect(sw, "GENERAL AUTHENTICATE 9B")?;
    mgmt_crypt(algorithm, &mut challenge, true)?;
    let answer = tlv(&reply, 0x7C).and_then(|dynamic| tlv(dynamic, 0x82));
    if answer != Some(challenge.as_slice()) {
        return Err(with_detail(
            plain("wallet.piv.mgmt"),
            "GENERAL AUTHENTICATE 9B: the card's answer did not match",
        ));
    }
    Ok(())
}

fn mgmt_crypt(algorithm: u8, block: &mut [u8], encrypt: bool) -> Result<(), KeyStoreError> {
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    let bad = || plain("wallet.piv.mgmt");
    match algorithm {
        ALG_TDES if block.len() == 8 => {
            let cipher = des::TdesEde3::new_from_slice(&DEFAULT_MGMT).map_err(|_| bad())?;
            let block = GenericArray::from_mut_slice(block);
            if encrypt {
                cipher.encrypt_block(block);
            } else {
                cipher.decrypt_block(block);
            }
        }
        ALG_AES192 if block.len() == 16 => {
            let cipher = aes::Aes192::new_from_slice(&DEFAULT_MGMT).map_err(|_| bad())?;
            let block = GenericArray::from_mut_slice(block);
            if encrypt {
                cipher.encrypt_block(block);
            } else {
                cipher.decrypt_block(block);
            }
        }
        _ => return Err(bad()),
    }
    Ok(())
}

fn generate(card: &pcsc::Card) -> Result<[u8; POINT_LEN], KeyStoreError> {
    let template = [
        0xAC,
        0x09,
        0x80,
        0x01,
        ALG_P256,
        0xAA,
        0x01,
        PIN_POLICY_ALWAYS,
        0xAB,
        0x01,
        TOUCH_POLICY_NEVER,
    ];
    let (body, sw) = apdu(card, 0x47, 0x00, SLOT, &template, true)?;
    if sw == SW_SECURITY {
        return Err(sw_detail(plain("wallet.piv.mgmt"), "GENERATE 82", sw));
    }
    expect(sw, "GENERATE 82")?;
    tlv(&body, 0x7F49)
        .and_then(|public| tlv(public, 0x86))
        .and_then(point_of)
        .ok_or_else(|| failed("GENERATE 82", sw))
}

fn kek_on(card: &pcsc::Card, pin: &str, salt: &[u8; 32]) -> Result<[u8; 32], KeyStoreError> {
    let point = salt_point(salt)?;
    // PinPolicy::Always is satisfied only when the PIN and the decipher
    // are the next two commands. Metadata in between would ask again.
    verify(card, pin)?;
    let mut data = vec![0x7C, 0x45, 0x82, 0x00, 0x85, 0x41];
    data.extend_from_slice(&point);
    let (mut body, sw) = apdu(card, 0x87, ALG_P256, SLOT, &data, true)?;
    if sw == SW_SECURITY {
        return Err(sw_detail(
            plain("wallet.piv.pin_again"),
            "GENERAL AUTHENTICATE 82",
            sw,
        ));
    }
    expect(sw, "GENERAL AUTHENTICATE 82")?;
    // The reply is the ECDH shared X, the secret the KEK comes from.
    let shared = tlv(&body, 0x7C)
        .and_then(|dynamic| tlv(dynamic, 0x82))
        .ok_or_else(|| failed("GENERAL AUTHENTICATE 82", sw))
        .and_then(shared_x_from_card);
    body.zeroize();
    let mut shared = shared?;
    let kek = derive_kek(&shared, salt);
    shared.zeroize();
    kek
}

/// One short APDU with CLA 00. `61xx` replies are collected with GET RESPONSE.
fn apdu(
    card: &pcsc::Card,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    expect_data: bool,
) -> Result<(Vec<u8>, u16), KeyStoreError> {
    let mut send = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        send.push(u8::try_from(data.len()).map_err(|_| failed("APDU", 0))?);
        send.extend_from_slice(data);
    }
    if expect_data {
        send.push(0x00);
    }
    let mut body = Vec::new();
    let mut buffer = [0u8; pcsc::MAX_BUFFER_SIZE];
    loop {
        let reply = card.transmit(&send, &mut buffer).map_err(map_pcsc);
        // The VERIFY APDU carries the PIN.
        send.zeroize();
        let reply = reply?;
        let Some((status, payload)) = reply.split_last_chunk::<2>().map(|(p, s)| (*s, p)) else {
            return Err(failed("APDU", 0));
        };
        body.extend_from_slice(payload);
        buffer.zeroize();
        if status[0] == 0x61 {
            send = vec![0x00, 0xC0, 0x00, 0x00, status[1]];
            continue;
        }
        return Ok((body, u16::from_be_bytes(status)));
    }
}

/// Top-level BER-TLV value for `tag`. PIV replies use one- and two-byte tags
/// and lengths up to two bytes.
fn tlv(data: &[u8], tag: u16) -> Option<&[u8]> {
    let mut rest = data;
    while !rest.is_empty() {
        let (found, after) = if rest[0] & 0x1F == 0x1F {
            (u16::from_be_bytes([rest[0], *rest.get(1)?]), &rest[2..])
        } else {
            (u16::from(rest[0]), &rest[1..])
        };
        let (len, after) = match *after.first()? {
            short @ 0..=0x7F => (usize::from(short), &after[1..]),
            0x81 => (usize::from(*after.get(1)?), &after[2..]),
            0x82 => (
                usize::from(u16::from_be_bytes([*after.get(1)?, *after.get(2)?])),
                &after[3..],
            ),
            _ => return None,
        };
        let value = after.get(..len)?;
        if found == tag {
            return Some(value);
        }
        rest = &after[len..];
    }
    None
}

fn point_of(raw: &[u8]) -> Option<[u8; POINT_LEN]> {
    let public = PublicKey::from_sec1_bytes(raw).ok()?;
    Some(uncompressed_point(&public))
}

fn expect(sw: u16, step: &str) -> Result<(), KeyStoreError> {
    if sw == SW_OK {
        Ok(())
    } else {
        Err(failed(step, sw))
    }
}

fn failed(step: &str, sw: u16) -> KeyStoreError {
    plain_args(
        "wallet.piv.device",
        &[("message", &format!("{step}: SW {sw:04X}"))],
    )
}

fn sw_detail(err: KeyStoreError, step: &str, sw: u16) -> KeyStoreError {
    with_detail(err, &format!("{step}: SW {sw:04X}"))
}

fn pcsc_detail(err: pcsc::Error) -> String {
    format!("PC/SC {err:?}: {err}")
}

fn map_pcsc(err: pcsc::Error) -> KeyStoreError {
    match err {
        pcsc::Error::NoReadersAvailable => plain("wallet.fido.none"),
        other => with_detail(plain("wallet.piv.pcsc"), &pcsc_detail(other)),
    }
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
    fn tlv_finds_nested_values_with_long_lengths_and_two_byte_tags() {
        let mut point = vec![0x86, 0x41, 0x04];
        point.extend_from_slice(&[0x11; 64]);
        let mut reply = vec![0x7F, 0x49, 0x81, 0x43];
        reply.extend_from_slice(&point);
        let public = tlv(&reply, 0x7F49).unwrap();
        assert_eq!(tlv(public, 0x86).unwrap().len(), 65);
        let meta = [0x01, 0x01, 0x11, 0x02, 0x02, 0x03, 0x01];
        assert_eq!(tlv(&meta, 0x02), Some(&[0x03, 0x01][..]));
        assert_eq!(tlv(&meta, 0x04), None);
        assert_eq!(tlv(&[0x01, 0x05, 0x00], 0x01), None);
    }

    #[test]
    fn the_management_cipher_round_trips_for_3des_and_aes192() {
        for (algorithm, len) in [(ALG_TDES, 8), (ALG_AES192, 16)] {
            let plain_block = vec![0x5A; len];
            let mut block = plain_block.clone();
            mgmt_crypt(algorithm, &mut block, true).unwrap();
            assert_ne!(block, plain_block);
            mgmt_crypt(algorithm, &mut block, false).unwrap();
            assert_eq!(block, plain_block);
        }
        assert!(mgmt_crypt(ALG_TDES, &mut [0; 16], true).is_err());
        assert!(mgmt_crypt(0x0C, &mut [0; 16], true).is_err());
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
