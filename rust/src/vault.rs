//! VORTEX-PQ vault — password-based encryption for secrets at rest (wallet seeds, key files).
//!
//! Argon2id stretches the password; the result feeds the same HKDF-SHA3-512 key schedule,
//! key commitment and VORTEX-256 / XChaCha20-Poly1305 cascade as the public-key envelope.
//! Keep in lockstep with src/pq/vault.ts and docs/SPEC.md.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::pq::{cascade_decrypt, cascade_encrypt, sha3_512, Error, MessageKeys};

const MAGIC: &[u8; 4] = b"VXPW";
const VERSION: u8 = 0x01;
const SUITE_ARGON2ID: u8 = 0x02;
const SALT_SIZE: usize = 32;
const HEADER_SIZE: usize = 4 + 1 + 1 + 4 + 4 + 1 + SALT_SIZE; // 47
pub const VAULT_OVERHEAD: usize = HEADER_SIZE + 32 + 2 * 16; // 111

/// Argon2id cost: memory in KiB, passes, lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m: u32,
    pub t: u32,
    pub p: u8,
}

/// Default cost: 256 MiB, 3 passes.
pub const DEFAULT_PARAMS: Argon2Params = Argon2Params { m: 262_144, t: 3, p: 1 };
/// Floor enforced on seal and open: OWASP's 2024 Argon2id minimum (19 MiB, 2 passes).
pub const MIN_PARAMS: Argon2Params = Argon2Params { m: 19_456, t: 2, p: 1 };
/// Ceiling enforced on seal and open, so a crafted header can't demand unbounded memory or time.
pub const MAX_PARAMS: Argon2Params = Argon2Params { m: 2_097_152, t: 64, p: 16 };

fn check(params: Argon2Params, allow_weak: bool) -> bool {
    let sane = params.p >= 1
        && params.t >= 1
        && params.m >= 8 * params.p as u32
        && params.m <= MAX_PARAMS.m
        && params.t <= MAX_PARAMS.t
        && params.p <= MAX_PARAMS.p;
    sane && (allow_weak || (params.m >= MIN_PARAMS.m && params.t >= MIN_PARAMS.t))
}

fn header(params: Argon2Params, salt: &[u8; SALT_SIZE]) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = VERSION;
    h[5] = SUITE_ARGON2ID;
    h[6..10].copy_from_slice(&params.m.to_be_bytes());
    h[10..14].copy_from_slice(&params.t.to_be_bytes());
    h[14] = params.p;
    h[15..].copy_from_slice(salt);
    h
}

fn stretch(password: &[u8], salt: &[u8], params: Argon2Params) -> Result<[u8; 64], Error> {
    let p = Params::new(params.m, params.t, params.p as u32, Some(64)).map_err(|_| Error::InvalidLength)?;
    let mut out = [0u8; 64];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| Error::InvalidLength)?;
    Ok(out)
}

/// Seals with explicit salt and parameters. `allow_weak` permits parameters below MIN_PARAMS (test vectors only).
pub fn vault_seal_with(
    password: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    params: Argon2Params,
    salt: &[u8; SALT_SIZE],
    allow_weak: bool,
) -> Result<Vec<u8>, Error> {
    if !check(params, allow_weak) {
        return Err(Error::InvalidLength);
    }
    let h = header(params, salt);
    let mut key = stretch(password, salt, params)?;
    let k = MessageKeys::derive(&key, sha3_512(&[&h]));
    key.zeroize();
    Ok([h.as_slice(), &cascade_encrypt(&k, plaintext, aad)?].concat())
}

/// Encrypts `plaintext` under `password` with a random salt and the default cost.
pub fn vault_seal(password: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_SIZE];
    getrandom::fill(&mut salt).map_err(|_| Error::Rng)?;
    vault_seal_with(password, plaintext, aad, DEFAULT_PARAMS, &salt, false)
}

/// Decrypts a vault. `allow_weak` permits parameters below MIN_PARAMS (test vectors only).
pub fn vault_open_with(password: &[u8], vault: &[u8], aad: &[u8], allow_weak: bool) -> Result<Vec<u8>, Error> {
    if vault.len() < VAULT_OVERHEAD {
        return Err(Error::Open);
    }
    let (h, body) = vault.split_at(HEADER_SIZE);
    if &h[0..4] != MAGIC || h[4] != VERSION || h[5] != SUITE_ARGON2ID {
        return Err(Error::Open);
    }
    let params = Argon2Params {
        m: u32::from_be_bytes(h[6..10].try_into().unwrap()),
        t: u32::from_be_bytes(h[10..14].try_into().unwrap()),
        p: h[14],
    };
    if !check(params, allow_weak) {
        return Err(Error::Open);
    }
    let mut key = stretch(password, &h[15..], params).map_err(|_| Error::Open)?;
    let k = MessageKeys::derive(&key, sha3_512(&[h]));
    key.zeroize();
    cascade_decrypt(&k, body, aad)
}

/// Decrypts a vault sealed with parameters at or above MIN_PARAMS.
pub fn vault_open(password: &[u8], vault: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    vault_open_with(password, vault, aad, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEAK: Argon2Params = Argon2Params { m: 64, t: 1, p: 1 };

    #[test]
    fn round_trip_and_rejections() {
        let v = vault_seal_with(b"pw", b"seed", b"wallet", WEAK, &[9; 32], true).unwrap();
        assert_eq!(v.len(), 4 + VAULT_OVERHEAD);
        assert_eq!(vault_open_with(b"pw", &v, b"wallet", true).unwrap(), b"seed");
        assert_eq!(vault_open_with(b"pW", &v, b"wallet", true), Err(Error::Open));
        assert_eq!(vault_open_with(b"pw", &v, b"other", true), Err(Error::Open));
        assert_eq!(vault_open(b"pw", &v, b"wallet"), Err(Error::Open), "weak params refused by default");
        for i in [0, 5, 7, 14, 20, 47, 79, v.len() - 1] {
            let mut t = v.clone();
            t[i] ^= 1;
            assert_eq!(vault_open_with(b"pw", &t, b"wallet", true), Err(Error::Open), "byte {i}");
        }
    }

    #[test]
    fn refuses_weak_or_absurd_params_on_seal() {
        assert!(vault_seal_with(b"pw", b"s", b"", WEAK, &[0; 32], false).is_err());
        let huge = Argon2Params { m: u32::MAX, t: 1, p: 1 };
        assert!(vault_seal_with(b"pw", b"s", b"", huge, &[0; 32], true).is_err());
    }
}
