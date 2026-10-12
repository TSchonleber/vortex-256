//! HSS / LMS — Leighton-Micali hash-based signatures (RFC 8554 + RFC 9858).
//! Rust port of src/lms/lms.ts; byte-for-byte identical keys and signatures.
//!
//! EDUCATIONAL / RESEARCH IMPLEMENTATION. Verified against the RFC 8554
//! Appendix F and RFC 9858 Appendix A test vectors, but not audited.
//!
//! Hash functions (selected by the typecodes in keys and signatures):
//!   SHA-256 (n = 32), SHA-256/192 (SHA-256 truncated to 24 bytes),
//!   SHAKE256/256 and SHAKE256/192 (first 32 / 24 bytes of SHAKE256).
//!
//! Keys are expanded deterministically from (SEED, I) with RFC 8554 Appendix A:
//! `x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`. The randomizer
//! C and HSS child SEED / I use the same formula with the reserved indices
//! 0xfffd / 0xfffe / 0xffff (the hash-sigs convention behind the RFC vectors).
//!
//! ###########################################################################
//! ##  STATEFUL SIGNATURES. Every one-time leaf may sign exactly ONE message. ##
//! ##                                                                         ##
//! ##  `lms_sign` / `hss_sign` take the private key BY VALUE and hand back a  ##
//! ##  `Signed { signature, next_key }`. Private keys are deliberately not    ##
//! ##  `Clone`, so the borrow checker stops you signing twice with one state. ##
//! ##  The required protocol:                                                 ##
//! ##    1. let Signed { signature, next_key } = hss_sign(key, msg)?;         ##
//! ##    2. durably persist next_key.serialize()  (fsync!)                    ##
//! ##    3. only THEN release `signature`                                     ##
//! ##  Nothing here can protect serialized copies, restored backups or VM     ##
//! ##  snapshots of the key. An exhausted key returns Err(Exhausted).         ##
//! ###########################################################################

use sha2::{Digest, Sha256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use std::sync::Arc;
use zeroize::Zeroize;

// ============================================================================
// Constants
// ============================================================================

/// Length of the I key-pair identifier (independent of the hash function).
pub const I_LEN: usize = 16;

/// Maximum HSS depth (RFC 8554 Section 6).
pub const HSS_MAX_LEVELS: usize = 8;

const D_PBLC: u16 = 0x8080;
const D_MESG: u16 = 0x8181;
const D_LEAF: u16 = 0x8282;
const D_INTR: u16 = 0x8383;

const DERIVE_RANDOMIZER: u16 = 0xfffd;
const DERIVE_CHILD_SEED: u16 = 0xfffe;
const DERIVE_CHILD_I: u16 = 0xffff;

// ============================================================================
// Parameter sets
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFamily {
    Sha256,
    Shake256,
}

/// An LM-OTS parameter set (RFC 8554 Table 1, RFC 9858 Table 1).
#[derive(Debug, PartialEq, Eq)]
pub struct LmotsParams {
    pub name: &'static str,
    pub typecode: u32,
    pub hash: HashFamily,
    pub n: usize,
    pub w: usize,
    pub p: usize,
    pub ls: u32,
}

/// An LMS parameter set (RFC 8554 Table 2, RFC 9858 Table 2).
#[derive(Debug, PartialEq, Eq)]
pub struct LmsParams {
    pub name: &'static str,
    pub typecode: u32,
    pub hash: HashFamily,
    pub m: usize,
    pub h: usize,
}

macro_rules! ots {
    ($name:literal, $t:literal, $hash:ident, $n:literal, $w:literal, $p:literal, $ls:literal) => {
        LmotsParams { name: $name, typecode: $t, hash: HashFamily::$hash, n: $n, w: $w, p: $p, ls: $ls }
    };
}

macro_rules! lms {
    ($name:literal, $t:literal, $hash:ident, $m:literal, $h:literal) => {
        LmsParams { name: $name, typecode: $t, hash: HashFamily::$hash, m: $m, h: $h }
    };
}

/// All LM-OTS parameter sets.
pub static LMOTS_PARAMS: [LmotsParams; 16] = [
    ots!("LMOTS_SHA256_N32_W1", 0x01, Sha256, 32, 1, 265, 7),
    ots!("LMOTS_SHA256_N32_W2", 0x02, Sha256, 32, 2, 133, 6),
    ots!("LMOTS_SHA256_N32_W4", 0x03, Sha256, 32, 4, 67, 4),
    ots!("LMOTS_SHA256_N32_W8", 0x04, Sha256, 32, 8, 34, 0),
    ots!("LMOTS_SHA256_N24_W1", 0x05, Sha256, 24, 1, 200, 8),
    ots!("LMOTS_SHA256_N24_W2", 0x06, Sha256, 24, 2, 101, 6),
    ots!("LMOTS_SHA256_N24_W4", 0x07, Sha256, 24, 4, 51, 4),
    ots!("LMOTS_SHA256_N24_W8", 0x08, Sha256, 24, 8, 26, 0),
    ots!("LMOTS_SHAKE_N32_W1", 0x09, Shake256, 32, 1, 265, 7),
    ots!("LMOTS_SHAKE_N32_W2", 0x0a, Shake256, 32, 2, 133, 6),
    ots!("LMOTS_SHAKE_N32_W4", 0x0b, Shake256, 32, 4, 67, 4),
    ots!("LMOTS_SHAKE_N32_W8", 0x0c, Shake256, 32, 8, 34, 0),
    ots!("LMOTS_SHAKE_N24_W1", 0x0d, Shake256, 24, 1, 200, 8),
    ots!("LMOTS_SHAKE_N24_W2", 0x0e, Shake256, 24, 2, 101, 6),
    ots!("LMOTS_SHAKE_N24_W4", 0x0f, Shake256, 24, 4, 51, 4),
    ots!("LMOTS_SHAKE_N24_W8", 0x10, Shake256, 24, 8, 26, 0),
];

/// All LMS parameter sets.
pub static LMS_PARAMS: [LmsParams; 20] = [
    lms!("LMS_SHA256_M32_H5", 0x05, Sha256, 32, 5),
    lms!("LMS_SHA256_M32_H10", 0x06, Sha256, 32, 10),
    lms!("LMS_SHA256_M32_H15", 0x07, Sha256, 32, 15),
    lms!("LMS_SHA256_M32_H20", 0x08, Sha256, 32, 20),
    lms!("LMS_SHA256_M32_H25", 0x09, Sha256, 32, 25),
    lms!("LMS_SHA256_M24_H5", 0x0a, Sha256, 24, 5),
    lms!("LMS_SHA256_M24_H10", 0x0b, Sha256, 24, 10),
    lms!("LMS_SHA256_M24_H15", 0x0c, Sha256, 24, 15),
    lms!("LMS_SHA256_M24_H20", 0x0d, Sha256, 24, 20),
    lms!("LMS_SHA256_M24_H25", 0x0e, Sha256, 24, 25),
    lms!("LMS_SHAKE_M32_H5", 0x0f, Shake256, 32, 5),
    lms!("LMS_SHAKE_M32_H10", 0x10, Shake256, 32, 10),
    lms!("LMS_SHAKE_M32_H15", 0x11, Shake256, 32, 15),
    lms!("LMS_SHAKE_M32_H20", 0x12, Shake256, 32, 20),
    lms!("LMS_SHAKE_M32_H25", 0x13, Shake256, 32, 25),
    lms!("LMS_SHAKE_M24_H5", 0x14, Shake256, 24, 5),
    lms!("LMS_SHAKE_M24_H10", 0x15, Shake256, 24, 10),
    lms!("LMS_SHAKE_M24_H15", 0x16, Shake256, 24, 15),
    lms!("LMS_SHAKE_M24_H20", 0x17, Shake256, 24, 20),
    lms!("LMS_SHAKE_M24_H25", 0x18, Shake256, 24, 25),
];

/// Look up an LM-OTS parameter set by typecode.
pub fn lmots_params(typecode: u32) -> Result<&'static LmotsParams, LmsError> {
    LMOTS_PARAMS.iter().find(|p| p.typecode == typecode).ok_or(LmsError::UnknownType(typecode))
}

/// Look up an LMS parameter set by typecode.
pub fn lms_params(typecode: u32) -> Result<&'static LmsParams, LmsError> {
    LMS_PARAMS.iter().find(|p| p.typecode == typecode).ok_or(LmsError::UnknownType(typecode))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LmsError {
    UnknownType(u32),
    Truncated,
    TrailingBytes,
    BadLength(&'static str),
    BadLevels,
    InconsistentState,
    /// Every one-time leaf has been used; the key can never sign again.
    Exhausted,
}

impl std::fmt::Display for LmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LmsError {}

// ============================================================================
// Byte and hash utilities
// ============================================================================

fn read_u32(buf: &[u8], off: usize) -> Result<u32, LmsError> {
    let b = buf.get(off..off + 4).ok_or(LmsError::Truncated)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn take(buf: &[u8], off: usize, len: usize) -> Result<Vec<u8>, LmsError> {
    buf.get(off..off + len).map(|s| s.to_vec()).ok_or(LmsError::Truncated)
}

/// H over the concatenation of `parts`, truncated to `len` bytes.
fn hash(family: HashFamily, len: usize, parts: &[&[u8]]) -> Vec<u8> {
    match family {
        HashFamily::Sha256 => {
            let mut h = Sha256::new();
            for p in parts {
                Digest::update(&mut h, p);
            }
            h.finalize()[..len].to_vec()
        }
        HashFamily::Shake256 => {
            let mut h = Shake256::default();
            for p in parts {
                h.update(p);
            }
            let mut out = vec![0u8; len];
            h.finalize_xof().read(&mut out);
            out
        }
    }
}

/// Appendix A style derivation: H(I || u32str(q) || u16str(j) || u8str(0xff) || SEED).
fn derive(family: HashFamily, len: usize, i: &[u8], q: u32, j: u16, seed: &[u8]) -> Vec<u8> {
    hash(family, len, &[i, &q.to_be_bytes(), &j.to_be_bytes(), &[0xff], seed])
}

// ============================================================================
// LM-OTS (RFC 8554 Section 4)
// ============================================================================

/// coef(S, i, w): the i-th w-bit digit of S, most significant first.
fn coef(s: &[u8], i: usize, w: usize) -> usize {
    let byte = s[i * w / 8] as usize;
    let shift = 8 - (w * (i % (8 / w)) + w);
    (byte >> shift) & ((1 << w) - 1)
}

fn checksum(ots: &LmotsParams, q: &[u8]) -> [u8; 2] {
    let max = (1usize << ots.w) - 1;
    let sum: usize = (0..ots.n * 8 / ots.w).map(|i| max - coef(q, i, ots.w)).sum();
    (((sum << ots.ls) & 0xffff) as u16).to_be_bytes()
}

fn message_digits(ots: &LmotsParams, i: &[u8], q: u32, c: &[u8], msg: &[u8]) -> Vec<usize> {
    let mut qc = hash(ots.hash, ots.n, &[i, &q.to_be_bytes(), &D_MESG.to_be_bytes(), c, msg]);
    let ck = checksum(ots, &qc);
    qc.extend_from_slice(&ck);
    (0..ots.p).map(|k| coef(&qc, k, ots.w)).collect()
}

/// Chain k from step `from` up to (not including) `to`:
/// tmp = H(I || u32str(q) || u16str(k) || u8str(j) || tmp).
fn chain(ots: &LmotsParams, i: &[u8], q: u32, k: usize, start: &[u8], from: usize, to: usize) -> Vec<u8> {
    let mut tmp = start.to_vec();
    for j in from..to {
        tmp = hash(ots.hash, ots.n, &[i, &q.to_be_bytes(), &(k as u16).to_be_bytes(), &[j as u8], &tmp]);
    }
    tmp
}

fn lmots_public_hash(ots: &LmotsParams, i: &[u8], q: u32, seed: &[u8]) -> Vec<u8> {
    let top = (1usize << ots.w) - 1;
    let ends: Vec<Vec<u8>> = (0..ots.p)
        .map(|k| chain(ots, i, q, k, &derive(ots.hash, ots.n, i, q, k as u16, seed), 0, top))
        .collect();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(ots.p + 3);
    let (qb, d) = (q.to_be_bytes(), D_PBLC.to_be_bytes());
    parts.extend([i, &qb[..], &d[..]]);
    parts.extend(ends.iter().map(|e| e.as_slice()));
    hash(ots.hash, ots.n, &parts)
}

/// A parsed LM-OTS signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LmotsSignature {
    pub ots: &'static LmotsParams,
    pub c: Vec<u8>,
    pub y: Vec<Vec<u8>>,
}

fn lmots_sign(ots: &'static LmotsParams, i: &[u8], q: u32, seed: &[u8], msg: &[u8]) -> LmotsSignature {
    let c = derive(ots.hash, ots.n, i, q, DERIVE_RANDOMIZER, seed);
    let digits = message_digits(ots, i, q, &c, msg);
    let y = digits
        .iter()
        .enumerate()
        .map(|(k, &a)| chain(ots, i, q, k, &derive(ots.hash, ots.n, i, q, k as u16, seed), 0, a))
        .collect();
    LmotsSignature { ots, c, y }
}

fn lmots_candidate(sig: &LmotsSignature, i: &[u8], q: u32, msg: &[u8]) -> Vec<u8> {
    let ots = sig.ots;
    let top = (1usize << ots.w) - 1;
    let digits = message_digits(ots, i, q, &sig.c, msg);
    let ends: Vec<Vec<u8>> = digits.iter().enumerate().map(|(k, &a)| chain(ots, i, q, k, &sig.y[k], a, top)).collect();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(ots.p + 3);
    let (qb, d) = (q.to_be_bytes(), D_PBLC.to_be_bytes());
    parts.extend([i, &qb[..], &d[..]]);
    parts.extend(ends.iter().map(|e| e.as_slice()));
    hash(ots.hash, ots.n, &parts)
}

impl LmotsSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.ots.typecode.to_be_bytes().to_vec();
        out.extend_from_slice(&self.c);
        self.y.iter().for_each(|y| out.extend_from_slice(y));
        out
    }

    fn decode_at(buf: &[u8], mut off: usize) -> Result<(Self, usize), LmsError> {
        let ots = lmots_params(read_u32(buf, off)?)?;
        off += 4;
        let c = take(buf, off, ots.n)?;
        off += ots.n;
        let mut y = Vec::with_capacity(ots.p);
        for _ in 0..ots.p {
            y.push(take(buf, off, ots.n)?);
            off += ots.n;
        }
        Ok((LmotsSignature { ots, c, y }, off))
    }
}

// ============================================================================
// LMS (RFC 8554 Section 5)
// ============================================================================

/// A parsed LMS public key: u32str(lms type) || u32str(ots type) || I || T[1].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LmsPublicKey {
    pub lms: &'static LmsParams,
    pub ots: &'static LmotsParams,
    pub i: [u8; I_LEN],
    pub root: Vec<u8>,
}

impl LmsPublicKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.lms.typecode.to_be_bytes().to_vec();
        out.extend_from_slice(&self.ots.typecode.to_be_bytes());
        out.extend_from_slice(&self.i);
        out.extend_from_slice(&self.root);
        out
    }

    fn decode_at(buf: &[u8], off: usize) -> Result<(Self, usize), LmsError> {
        let lms = lms_params(read_u32(buf, off)?)?;
        let ots = lmots_params(read_u32(buf, off + 4)?)?;
        let i: [u8; I_LEN] = take(buf, off + 8, I_LEN)?.try_into().unwrap();
        let root = take(buf, off + 8 + I_LEN, lms.m)?;
        Ok((LmsPublicKey { lms, ots, i, root }, off + 8 + I_LEN + lms.m))
    }

    /// Parse a wire-format LMS public key (exact length required).
    pub fn decode(buf: &[u8]) -> Result<Self, LmsError> {
        let (pk, end) = Self::decode_at(buf, 0)?;
        if end != buf.len() {
            return Err(LmsError::TrailingBytes);
        }
        Ok(pk)
    }
}

/// A parsed LMS signature: u32str(q) || lmots_signature || u32str(type) || path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LmsSignature {
    pub q: u32,
    pub ots_sig: LmotsSignature,
    pub lms: &'static LmsParams,
    pub path: Vec<Vec<u8>>,
}

impl LmsSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.q.to_be_bytes().to_vec();
        out.extend(self.ots_sig.encode());
        out.extend_from_slice(&self.lms.typecode.to_be_bytes());
        self.path.iter().for_each(|p| out.extend_from_slice(p));
        out
    }

    fn decode_at(buf: &[u8], off: usize) -> Result<(Self, usize), LmsError> {
        let q = read_u32(buf, off)?;
        let (ots_sig, mut off) = LmotsSignature::decode_at(buf, off + 4)?;
        let lms = lms_params(read_u32(buf, off)?)?;
        off += 4;
        let mut path = Vec::with_capacity(lms.h);
        for _ in 0..lms.h {
            path.push(take(buf, off, lms.m)?);
            off += lms.m;
        }
        Ok((LmsSignature { q, ots_sig, lms, path }, off))
    }

    /// Parse a wire-format LMS signature (exact length required).
    pub fn decode(buf: &[u8]) -> Result<Self, LmsError> {
        let (sig, end) = Self::decode_at(buf, 0)?;
        if end != buf.len() {
            return Err(LmsError::TrailingBytes);
        }
        Ok(sig)
    }
}

/// Result of a stateful signing operation. Persist `next_key` BEFORE releasing
/// `signature`; the key you passed in has been consumed.
#[must_use = "persist next_key before releasing the signature"]
pub struct Signed<K> {
    pub signature: Vec<u8>,
    pub next_key: K,
}

/// LMS private key STATE (deliberately not `Clone`). `q` is the next unused leaf;
/// `tree` caches the Merkle tree (tree[r] = T[r]), recomputable from (SEED, I).
pub struct LmsPrivateKey {
    lms: &'static LmsParams,
    ots: &'static LmotsParams,
    i: [u8; I_LEN],
    seed: Vec<u8>,
    q: u32,
    tree: Arc<Vec<Vec<u8>>>,
}

impl Drop for LmsPrivateKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl std::fmt::Debug for LmsPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LmsPrivateKey {{ {} / {}, q: {} }}", self.lms.name, self.ots.name, self.q)
    }
}

/// Full Merkle tree: 2^h LM-OTS public keys — practical up to h = 10..15.
fn build_tree(lms: &LmsParams, ots: &LmotsParams, i: &[u8], seed: &[u8]) -> Vec<Vec<u8>> {
    let leaves = 1usize << lms.h;
    let mut tree = vec![Vec::new(); 2 * leaves];
    for q in 0..leaves {
        let r = (leaves + q) as u32;
        let k = lmots_public_hash(ots, i, q as u32, seed);
        tree[leaves + q] = hash(lms.hash, lms.m, &[i, &r.to_be_bytes(), &D_LEAF.to_be_bytes(), &k]);
    }
    for r in (1..leaves).rev() {
        tree[r] = hash(lms.hash, lms.m, &[i, &(r as u32).to_be_bytes(), &D_INTR.to_be_bytes(), &tree[2 * r], &tree[2 * r + 1]]);
    }
    tree
}

impl LmsPrivateKey {
    /// Restore (or create, with q = 0) an LMS private key state from (SEED, I).
    pub fn from_seed(lms_type: u32, ots_type: u32, seed: &[u8], i: &[u8], q: u32) -> Result<Self, LmsError> {
        let lms = lms_params(lms_type)?;
        let ots = lmots_params(ots_type)?;
        let i: [u8; I_LEN] = i.try_into().map_err(|_| LmsError::BadLength("I"))?;
        if seed.len() != lms.m {
            return Err(LmsError::BadLength("SEED"));
        }
        if q as u64 > 1u64 << lms.h {
            return Err(LmsError::InconsistentState);
        }
        let tree = Arc::new(build_tree(lms, ots, &i, seed));
        Ok(LmsPrivateKey { lms, ots, i, seed: seed.to_vec(), q, tree })
    }

    pub fn lms(&self) -> &'static LmsParams {
        self.lms
    }
    pub fn ots(&self) -> &'static LmotsParams {
        self.ots
    }
    pub fn i(&self) -> &[u8; I_LEN] {
        &self.i
    }
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }
    /// Next unused leaf.
    pub fn q(&self) -> u32 {
        self.q
    }

    /// Number of signatures this state can still produce.
    pub fn remaining(&self) -> u64 {
        (1u64 << self.lms.h) - self.q as u64
    }

    /// Wire-format LMS public key.
    pub fn public_key(&self) -> Vec<u8> {
        LmsPublicKey { lms: self.lms, ots: self.ots, i: self.i, root: self.tree[1].clone() }.encode()
    }

    /// The same key at another leaf, sharing the tree cache (internal use only).
    fn at(&self, q: u32) -> Self {
        LmsPrivateKey { lms: self.lms, ots: self.ots, i: self.i, seed: self.seed.clone(), q, tree: Arc::clone(&self.tree) }
    }

    /// The fresh child key that this key's next leaf (q) will sign:
    /// SEED' = H(I||u32str(q)||u16str(0xfffe)||0xff||SEED), I' = first 16 bytes of
    /// the same with 0xffff, H = the child's LMS hash (matches RFC 8554 Test Case 2).
    pub fn derive_child(&self, lms_type: u32, ots_type: u32) -> Result<Self, LmsError> {
        let lms = lms_params(lms_type)?;
        let seed = derive(lms.hash, lms.m, &self.i, self.q, DERIVE_CHILD_SEED, &self.seed);
        let i = derive(lms.hash, lms.m, &self.i, self.q, DERIVE_CHILD_I, &self.seed);
        Self::from_seed(lms_type, ots_type, &seed, &i[..I_LEN], 0)
    }

    /// Serialize (NOT an RFC format): u32 lms type || u32 ots type || u32 q || I || SEED.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.lms.typecode.to_be_bytes().to_vec();
        out.extend_from_slice(&self.ots.typecode.to_be_bytes());
        out.extend_from_slice(&self.q.to_be_bytes());
        out.extend_from_slice(&self.i);
        out.extend_from_slice(&self.seed);
        out
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, LmsError> {
        let lms = lms_params(read_u32(buf, 0)?)?;
        let ots = read_u32(buf, 4)?;
        let q = read_u32(buf, 8)?;
        if buf.len() != 12 + I_LEN + lms.m {
            return Err(LmsError::BadLength("LMS private key"));
        }
        Self::from_seed(lms.typecode, ots, &buf[12 + I_LEN..], &buf[12..12 + I_LEN], q)
    }
}

/// Generate an LMS key pair deterministically from (SEED, I): (public key, private key).
pub fn lms_keygen(lms_type: u32, ots_type: u32, seed: &[u8], i: &[u8]) -> Result<(Vec<u8>, LmsPrivateKey), LmsError> {
    let key = LmsPrivateKey::from_seed(lms_type, ots_type, seed, i, 0)?;
    Ok((key.public_key(), key))
}

/// Sign with leaf `key.q`, consuming the state. STATEFUL — see the module docs.
pub fn lms_sign(key: LmsPrivateKey, msg: &[u8]) -> Result<Signed<LmsPrivateKey>, LmsError> {
    if key.remaining() == 0 {
        return Err(LmsError::Exhausted);
    }
    let (lms, q) = (key.lms, key.q);
    let ots_sig = lmots_sign(key.ots, &key.i, q, &key.seed, msg);
    let mut node = (1usize << lms.h) + q as usize;
    let mut path = Vec::with_capacity(lms.h);
    for _ in 0..lms.h {
        path.push(key.tree[node ^ 1].clone());
        node >>= 1;
    }
    let signature = LmsSignature { q, ots_sig, lms, path }.encode();
    Ok(Signed { signature, next_key: key.at(q + 1) })
}

/// Verify an LMS signature (Algorithm 6). Malformed input -> false.
pub fn lms_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    match (LmsPublicKey::decode(public_key), LmsSignature::decode(signature)) {
        (Ok(pk), Ok(sig)) => lms_verify_parsed(&pk, msg, &sig),
        _ => false,
    }
}

fn lms_verify_parsed(pk: &LmsPublicKey, msg: &[u8], sig: &LmsSignature) -> bool {
    if sig.lms.typecode != pk.lms.typecode || sig.ots_sig.ots.typecode != pk.ots.typecode {
        return false;
    }
    let lms = pk.lms;
    if sig.q as u64 >= 1u64 << lms.h {
        return false;
    }
    let kc = lmots_candidate(&sig.ots_sig, &pk.i, sig.q, msg);
    let mut node = (1u32 << lms.h) + sig.q;
    let mut tmp = hash(lms.hash, lms.m, &[&pk.i, &node.to_be_bytes(), &D_LEAF.to_be_bytes(), &kc]);
    let mut k = 0;
    while node > 1 {
        let parent = (node >> 1).to_be_bytes();
        let (left, right) = if node & 1 == 1 { (&sig.path[k], &tmp) } else { (&tmp, &sig.path[k]) };
        tmp = hash(lms.hash, lms.m, &[&pk.i, &parent, &D_INTR.to_be_bytes(), left, right]);
        node >>= 1;
        k += 1;
    }
    tmp == pk.root
}

// ============================================================================
// HSS (RFC 8554 Section 6)
// ============================================================================

/// A parsed HSS public key: u32str(L) || top-level LMS public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HssPublicKey {
    pub levels: u32,
    pub top: LmsPublicKey,
}

impl HssPublicKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.levels.to_be_bytes().to_vec();
        out.extend(self.top.encode());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, LmsError> {
        let levels = read_u32(buf, 0)?;
        if !(1..=HSS_MAX_LEVELS).contains(&(levels as usize)) {
            return Err(LmsError::BadLevels);
        }
        Ok(HssPublicKey { levels, top: LmsPublicKey::decode(&buf[4..])? })
    }
}

/// A parsed HSS signature: u32str(Nspk) || (sig_i || pub_{i+1})* || final sig.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HssSignature {
    pub signed_public_keys: Vec<(LmsSignature, LmsPublicKey)>,
    pub sig: LmsSignature,
}

impl HssSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = (self.signed_public_keys.len() as u32).to_be_bytes().to_vec();
        for (s, p) in &self.signed_public_keys {
            out.extend(s.encode());
            out.extend(p.encode());
        }
        out.extend(self.sig.encode());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, LmsError> {
        let nspk = read_u32(buf, 0)? as usize;
        if nspk > HSS_MAX_LEVELS - 1 {
            return Err(LmsError::BadLevels);
        }
        let mut off = 4;
        let mut signed_public_keys = Vec::with_capacity(nspk);
        for _ in 0..nspk {
            let (s, end) = LmsSignature::decode_at(buf, off)?;
            let (p, end) = LmsPublicKey::decode_at(buf, end)?;
            signed_public_keys.push((s, p));
            off = end;
        }
        let (sig, end) = LmsSignature::decode_at(buf, off)?;
        if end != buf.len() {
            return Err(LmsError::TrailingBytes);
        }
        Ok(HssSignature { signed_public_keys, sig })
    }
}

/// HSS private key STATE (not `Clone`). keys[0] is the top tree; signed_pub_keys[i]
/// is keys[i]'s signature (made with leaf keys[i].q - 1) || keys[i+1]'s public key.
#[derive(Debug)]
pub struct HssPrivateKey {
    keys: Vec<LmsPrivateKey>,
    signed_pub_keys: Vec<Vec<u8>>,
}

impl HssPrivateKey {
    /// Build an HSS state from explicit per-level LMS keys (top first). Each parent
    /// signs its child's public key with its current leaf.
    pub fn from_lms_keys(keys: Vec<LmsPrivateKey>) -> Result<Self, LmsError> {
        if keys.is_empty() || keys.len() > HSS_MAX_LEVELS {
            return Err(LmsError::BadLevels);
        }
        let mut out: Vec<LmsPrivateKey> = Vec::with_capacity(keys.len());
        let mut signed_pub_keys = Vec::new();
        let mut iter = keys.into_iter();
        out.push(iter.next().unwrap());
        for child in iter {
            let child_pub = child.public_key();
            let parent = out.pop().unwrap();
            let Signed { mut signature, next_key } = lms_sign(parent, &child_pub)?;
            signature.extend_from_slice(&child_pub);
            signed_pub_keys.push(signature);
            out.push(next_key);
            out.push(child);
        }
        Ok(HssPrivateKey { keys: out, signed_pub_keys })
    }

    pub fn keys(&self) -> &[LmsPrivateKey] {
        &self.keys
    }

    /// Wire-format HSS public key.
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = (self.keys.len() as u32).to_be_bytes().to_vec();
        out.extend(self.keys[0].public_key());
        out
    }

    /// Serialize (NOT an RFC format): u32 L || per level (u32 len || LMS key).
    /// Signed child keys are regenerated on load (C is deterministic).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = (self.keys.len() as u32).to_be_bytes().to_vec();
        for k in &self.keys {
            let s = k.serialize();
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend(s);
        }
        out
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, LmsError> {
        let l = read_u32(buf, 0)? as usize;
        if !(1..=HSS_MAX_LEVELS).contains(&l) {
            return Err(LmsError::BadLevels);
        }
        let mut keys = Vec::with_capacity(l);
        let mut off = 4;
        for _ in 0..l {
            let len = read_u32(buf, off)? as usize;
            keys.push(LmsPrivateKey::deserialize(buf.get(off + 4..off + 4 + len).ok_or(LmsError::Truncated)?)?);
            off += 4 + len;
        }
        if off != buf.len() {
            return Err(LmsError::TrailingBytes);
        }
        let mut signed_pub_keys = Vec::with_capacity(l - 1);
        for k in 0..l - 1 {
            let parent = &keys[k];
            if parent.q == 0 {
                return Err(LmsError::InconsistentState);
            }
            // Re-create the signature parent made with leaf q - 1 over the same child key.
            let child_pub = keys[k + 1].public_key();
            let Signed { mut signature, .. } = lms_sign(parent.at(parent.q - 1), &child_pub)?;
            signature.extend_from_slice(&child_pub);
            signed_pub_keys.push(signature);
        }
        Ok(HssPrivateKey { keys, signed_pub_keys })
    }
}

/// Generate an HSS key pair from the top-level (SEED, I); `levels` = [(lms type, ots type)], top first.
pub fn hss_keygen(levels: &[(u32, u32)], seed: &[u8], i: &[u8]) -> Result<(Vec<u8>, HssPrivateKey), LmsError> {
    if levels.is_empty() || levels.len() > HSS_MAX_LEVELS {
        return Err(LmsError::BadLevels);
    }
    let mut keys = vec![LmsPrivateKey::from_seed(levels[0].0, levels[0].1, seed, i, 0)?];
    for &(lms, ots) in &levels[1..] {
        let child = keys.last().unwrap().derive_child(lms, ots)?;
        keys.push(child);
    }
    let key = HssPrivateKey::from_lms_keys(keys)?;
    Ok((key.public_key(), key))
}

/// Sign, consuming the state. STATEFUL — see the module docs. When the bottom tree
/// is used up, the deepest parent with leaves left signs a freshly derived child.
pub fn hss_sign(key: HssPrivateKey, msg: &[u8]) -> Result<Signed<HssPrivateKey>, LmsError> {
    let HssPrivateKey { mut keys, mut signed_pub_keys } = key;
    let l = keys.len();
    let d = (0..l).rev().find(|&k| keys[k].remaining() > 0).ok_or(LmsError::Exhausted)?;
    for k in d..l - 1 {
        let fresh = keys[k].derive_child(keys[k + 1].lms.typecode, keys[k + 1].ots.typecode)?;
        let fresh_pub = fresh.public_key();
        keys[k + 1] = fresh; // drops the exhausted child
        let parent = keys.remove(k);
        let Signed { mut signature, next_key } = lms_sign(parent, &fresh_pub)?;
        keys.insert(k, next_key);
        signature.extend_from_slice(&fresh_pub);
        signed_pub_keys[k] = signature;
    }
    let bottom = keys.pop().unwrap();
    let Signed { signature: last, next_key } = lms_sign(bottom, msg)?;
    keys.push(next_key);
    let mut signature = ((l - 1) as u32).to_be_bytes().to_vec();
    signed_pub_keys.iter().for_each(|s| signature.extend_from_slice(s));
    signature.extend(last);
    Ok(Signed { signature, next_key: HssPrivateKey { keys, signed_pub_keys } })
}

/// Verify an HSS signature (Algorithm 6a). Malformed input -> false.
pub fn hss_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    let (pk, sig) = match (HssPublicKey::decode(public_key), HssSignature::decode(signature)) {
        (Ok(pk), Ok(sig)) => (pk, sig),
        _ => return false,
    };
    if sig.signed_public_keys.len() + 1 != pk.levels as usize {
        return false;
    }
    let mut key = &pk.top;
    for (s, next) in &sig.signed_public_keys {
        if !lms_verify_parsed(key, &next.encode(), s) {
            return false;
        }
        key = next;
    }
    lms_verify_parsed(key, msg, &sig.sig)
}
