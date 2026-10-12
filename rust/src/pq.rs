//! VORTEX-PQ v1 — hybrid post-quantum public-key encryption.
//!
//! ML-KEM-1024 + X25519 hybrid KEM, HKDF-SHA3-512, key commitment, and a cascade of
//! VORTEX-256-AEAD inside XChaCha20-Poly1305. The normative description is docs/SPEC.md;
//! keep this file and src/pq/envelope.ts in lockstep with it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::SimpleHkdf;
use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem1024};
use sha3::{Digest, Sha3_256, Sha3_512};
use shake::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{aead_decrypt, aead_encrypt};

// ============================================================================
// Constants
// ============================================================================

const LABEL: &[u8] = b"VORTEX-PQ-v1";
const MAGIC: &[u8; 4] = b"VXPQ";
const VERSION: u8 = 0x01;
const SUITE_MLKEM1024_X25519: u8 = 0x01;

pub const SEED_SIZE: usize = 32;
pub const ESEED_SIZE: usize = 64;
const MLKEM_PK: usize = 1568;
const MLKEM_CT: usize = 1568;
const X25519_LEN: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = MLKEM_PK + X25519_LEN; // 1600
pub const KEM_CIPHERTEXT_SIZE: usize = MLKEM_CT + X25519_LEN; // 1600
pub const SHARED_SECRET_SIZE: usize = 64;
const HEADER_SIZE: usize = 6;
const COMMIT_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
pub const OVERHEAD: usize = HEADER_SIZE + KEM_CIPHERTEXT_SIZE + COMMIT_SIZE + 2 * TAG_SIZE; // 1670

/// Errors. Every decryption failure is reported as `Open`, so callers can't learn which layer rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    InvalidPublicKey,
    LowOrderPoint,
    Rng,
    Open,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "VORTEX-PQ: invalid input length",
            Error::InvalidPublicKey => "VORTEX-PQ: invalid public key",
            Error::LowOrderPoint => "VORTEX-PQ: X25519 produced an all-zero shared secret",
            Error::Rng => "VORTEX-PQ: random number generator failed",
            Error::Open => "VORTEX-PQ: envelope could not be opened",
        })
    }
}

impl std::error::Error for Error {}

// ============================================================================
// Key generation
// ============================================================================

struct ExpandedKey {
    mlkem: DecapsulationKey<MlKem1024>,
    mlkem_public: Vec<u8>,
    x25519: StaticSecret,
    x25519_public: [u8; 32],
}

fn expand_seed(seed: &[u8]) -> Result<ExpandedKey, Error> {
    if seed.len() != SEED_SIZE {
        return Err(Error::InvalidLength);
    }
    let mut e = [0u8; 96];
    let mut xof = Shake256::default();
    xof.update(LABEL);
    xof.update(b"/keygen");
    xof.update(seed);
    xof.finalize_xof().read(&mut e);

    // FIPS 203 KeyGen_internal(d, z) with d || z = e[0..64].
    let mlkem = DecapsulationKey::<MlKem1024>::from_seed(e[..64].try_into().expect("64 bytes"));
    let mlkem_public = mlkem.encapsulation_key().to_bytes().to_vec();
    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&e[64..96]);
    let x25519 = StaticSecret::from(sk_x);
    let x25519_public = PublicKey::from(&x25519).to_bytes();
    sk_x.zeroize();
    e.zeroize();
    Ok(ExpandedKey { mlkem, mlkem_public, x25519, x25519_public })
}

/// Derives the 1600-byte public key for a 32-byte secret seed.
pub fn public_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, Error> {
    let k = expand_seed(seed)?;
    Ok([k.mlkem_public.as_slice(), &k.x25519_public].concat())
}

/// Generates a fresh key pair from the OS RNG. The secret key is the 32-byte seed.
pub fn generate_key_pair() -> Result<([u8; SEED_SIZE], Vec<u8>), Error> {
    let mut seed = [0u8; SEED_SIZE];
    getrandom::fill(&mut seed).map_err(|_| Error::Rng)?;
    let pk = public_key_from_seed(&seed)?;
    Ok((seed, pk))
}

// ============================================================================
// Hybrid KEM
// ============================================================================

fn combine(ss_m: &[u8], ss_x: &[u8], ct_m: &[u8], ct_x: &[u8], pk_m: &[u8], pk_x: &[u8]) -> [u8; SHARED_SECRET_SIZE] {
    let mut h = Sha3_512::new();
    Digest::update(&mut h, LABEL);
    Digest::update(&mut h, b"/combine");
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, Sha3_256::digest(ct_m));
    Digest::update(&mut h, Sha3_256::digest(pk_m));
    h.finalize().into()
}

fn dh(secret: &StaticSecret, public: &[u8]) -> Result<[u8; 32], Error> {
    let pk: [u8; 32] = public.try_into().map_err(|_| Error::InvalidLength)?;
    let ss = secret.diffie_hellman(&PublicKey::from(pk));
    if !ss.was_contributory() {
        return Err(Error::LowOrderPoint);
    }
    Ok(ss.to_bytes())
}

/// Encapsulates to `public_key` using the 64-byte `eseed` (randomness). Prefer `encapsulate`.
pub fn encapsulate_with_eseed(public_key: &[u8], eseed: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_SIZE]), Error> {
    if public_key.len() != PUBLIC_KEY_SIZE || eseed.len() != ESEED_SIZE {
        return Err(Error::InvalidLength);
    }
    let (pk_m, pk_x) = public_key.split_at(MLKEM_PK);
    let ek = EncapsulationKey::<MlKem1024>::new(pk_m.try_into().map_err(|_| Error::InvalidLength)?)
        .map_err(|_| Error::InvalidPublicKey)?;
    let (ct_m, ss_m) = ek.encapsulate_deterministic(eseed[..32].try_into().expect("32 bytes"));

    let mut ek_x = [0u8; 32];
    ek_x.copy_from_slice(&eseed[32..64]);
    let eph = StaticSecret::from(ek_x);
    ek_x.zeroize();
    let ct_x = PublicKey::from(&eph).to_bytes();
    let mut ss_x = dh(&eph, pk_x)?;

    let ss = combine(&ss_m, &ss_x, &ct_m, &ct_x, pk_m, pk_x);
    ss_x.zeroize();
    Ok(([ct_m.as_slice(), &ct_x].concat(), ss))
}

/// Encapsulates a fresh shared secret to `public_key`.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_SIZE]), Error> {
    let mut eseed = [0u8; ESEED_SIZE];
    getrandom::fill(&mut eseed).map_err(|_| Error::Rng)?;
    let r = encapsulate_with_eseed(public_key, &eseed);
    eseed.zeroize();
    r
}

pub fn decapsulate(seed: &[u8], ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_SIZE], Error> {
    if ciphertext.len() != KEM_CIPHERTEXT_SIZE {
        return Err(Error::InvalidLength);
    }
    let k = expand_seed(seed)?;
    decapsulate_expanded(&k, ciphertext)
}

fn decapsulate_expanded(k: &ExpandedKey, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_SIZE], Error> {
    let (ct_m, ct_x) = ciphertext.split_at(MLKEM_CT);
    let ss_m = k.mlkem.decapsulate(ct_m.try_into().map_err(|_| Error::InvalidLength)?);
    let mut ss_x = dh(&k.x25519, ct_x)?;
    let ss = combine(&ss_m, &ss_x, ct_m, ct_x, &k.mlkem_public, &k.x25519_public);
    ss_x.zeroize();
    Ok(ss)
}

// ============================================================================
// Envelope
// ============================================================================

/// HKDF-SHA3-512 key schedule shared by every VORTEX-PQ suite (docs/SPEC.md).
pub(crate) struct MessageKeys {
    th: [u8; 64],
    okm: [u8; 132],
}

impl MessageKeys {
    pub(crate) fn derive(ikm: &[u8], th: [u8; 64]) -> Self {
        let mut okm = [0u8; 132];
        SimpleHkdf::<Sha3_512>::new(Some(LABEL), ikm).expand(&th, &mut okm).expect("132 <= 255 * 64");
        MessageKeys { th, okm }
    }
    fn k1(&self) -> &[u8] { &self.okm[0..32] }
    fn n1(&self) -> &[u8] { &self.okm[32..44] }
    fn k2(&self) -> &[u8] { &self.okm[44..76] }
    fn n2(&self) -> &[u8] { &self.okm[76..100] }
    fn commit(&self) -> &[u8] { &self.okm[100..132] }
}

impl Drop for MessageKeys {
    fn drop(&mut self) {
        self.okm.zeroize();
    }
}

pub(crate) fn sha3_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// VORTEX-256-AEAD inside XChaCha20-Poly1305, both bound to th || aad. Returns commit || outer.
pub(crate) fn cascade_encrypt(k: &MessageKeys, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let ad = [k.th.as_slice(), aad].concat();
    let (c1, t1) = aead_encrypt(k.k1(), k.n1(), plaintext, &ad).map_err(|_| Error::InvalidLength)?;
    let inner = [c1.as_slice(), &t1].concat();
    let outer = XChaCha20Poly1305::new_from_slice(k.k2())
        .expect("32-byte key")
        .encrypt(&XNonce::try_from(k.n2()).expect("24-byte nonce"), Payload { msg: &inner, aad: &ad })
        .map_err(|_| Error::InvalidLength)?;
    Ok([k.commit(), &outer].concat())
}

/// Inverse of cascade_encrypt. Checks the commitment before touching either AEAD.
pub(crate) fn cascade_decrypt(k: &MessageKeys, body: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() < COMMIT_SIZE + 2 * TAG_SIZE {
        return Err(Error::Open);
    }
    let (commit, outer) = body.split_at(COMMIT_SIZE);
    if !bool::from(commit.ct_eq(k.commit())) {
        return Err(Error::Open);
    }
    let ad = [k.th.as_slice(), aad].concat();
    let inner = XChaCha20Poly1305::new_from_slice(k.k2())
        .expect("32-byte key")
        .decrypt(&XNonce::try_from(k.n2()).expect("24-byte nonce"), Payload { msg: outer, aad: &ad })
        .map_err(|_| Error::Open)?;
    let (c1, t1) = inner.split_at(inner.len() - TAG_SIZE);
    match aead_decrypt(k.k1(), k.n1(), c1, t1, &ad) {
        Ok(Some(pt)) => Ok(pt),
        _ => Err(Error::Open),
    }
}

fn header() -> [u8; HEADER_SIZE] {
    [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, SUITE_MLKEM1024_X25519]
}

/// Seals with caller-supplied randomness. Exists for test vectors; use `seal`.
pub fn seal_with_eseed(public_key: &[u8], plaintext: &[u8], aad: &[u8], eseed: &[u8]) -> Result<Vec<u8>, Error> {
    let header = header();
    let (kem_ct, mut ss) = encapsulate_with_eseed(public_key, eseed)?;
    let k = MessageKeys::derive(&ss, sha3_512(&[&header, &kem_ct, public_key]));
    ss.zeroize();
    Ok([header.as_slice(), &kem_ct, &cascade_encrypt(&k, plaintext, aad)?].concat())
}

/// Encrypts `plaintext` to `public_key`. `aad` is authenticated but not encrypted.
pub fn seal(public_key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let mut eseed = [0u8; ESEED_SIZE];
    getrandom::fill(&mut eseed).map_err(|_| Error::Rng)?;
    let r = seal_with_eseed(public_key, plaintext, aad, &eseed);
    eseed.zeroize();
    r
}

/// Decrypts an envelope with the recipient's 32-byte seed.
pub fn open(seed: &[u8], envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if envelope.len() < OVERHEAD {
        return Err(Error::Open);
    }
    let (header, rest) = envelope.split_at(HEADER_SIZE);
    if header != self::header() {
        return Err(Error::Open);
    }
    let (kem_ct, rest) = rest.split_at(KEM_CIPHERTEXT_SIZE);

    let ek = expand_seed(seed).map_err(|_| Error::Open)?;
    let mut ss = decapsulate_expanded(&ek, kem_ct).map_err(|_| Error::Open)?;
    let public_key = [ek.mlkem_public.as_slice(), &ek.x25519_public].concat();
    let k = MessageKeys::derive(&ss, sha3_512(&[header, kem_ct, &public_key]));
    ss.zeroize();
    cascade_decrypt(&k, rest, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (seed, pk) = generate_key_pair().unwrap();
        for n in [0usize, 1, 16, 17, 1000] {
            let pt: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let env = seal(&pk, &pt, b"aad").unwrap();
            assert_eq!(env.len(), n + OVERHEAD);
            assert_eq!(open(&seed, &env, b"aad").unwrap(), pt);
            assert_eq!(open(&seed, &env, b"other"), Err(Error::Open));
        }
    }

    #[test]
    fn tamper_rejected() {
        let (seed, pk) = generate_key_pair().unwrap();
        let env = seal(&pk, &[7u8; 64], b"").unwrap();
        for i in [0, 5, 6, 900, 1605, 1606, 1637, 1638, env.len() - 1] {
            let mut t = env.clone();
            t[i] ^= 1;
            assert_eq!(open(&seed, &t, b""), Err(Error::Open), "byte {i}");
        }
    }

    #[test]
    fn wrong_recipient_rejected() {
        let (_, pk) = generate_key_pair().unwrap();
        let (other, _) = generate_key_pair().unwrap();
        let env = seal(&pk, b"x", b"").unwrap();
        assert_eq!(open(&other, &env, b""), Err(Error::Open));
    }

    #[test]
    fn low_order_share_rejected() {
        let (seed, pk) = generate_key_pair().unwrap();
        let (mut ct, _) = encapsulate(&pk).unwrap();
        ct[MLKEM_CT..].fill(0);
        assert_eq!(decapsulate(&seed, &ct), Err(Error::LowOrderPoint));
    }
}
