/**
 * HSS / LMS — Leighton-Micali Hash-Based Signatures (RFC 8554 + RFC 9858)
 *
 * EDUCATIONAL / RESEARCH IMPLEMENTATION
 * Verified against the RFC 8554 Appendix F and RFC 9858 Appendix A test vectors,
 * but NOT audited. Signing is not constant-time.
 *
 * Layers:
 *   - LM-OTS: Winternitz one-time signatures (RFC 8554 Section 4)
 *   - LMS:    Merkle tree of 2^h LM-OTS keys (RFC 8554 Section 5)
 *   - HSS:    hierarchy of 1..8 LMS trees (RFC 8554 Section 6)
 *
 * Hash functions (selected by the typecodes in keys and signatures):
 *   - SHA-256        (RFC 8554, n = m = 32)
 *   - SHA-256/192    (RFC 9858, SHA-256 truncated to 24 bytes)
 *   - SHAKE256/256   (RFC 9858, first 32 bytes of SHAKE256)
 *   - SHAKE256/192   (RFC 9858, first 24 bytes of SHAKE256)
 *
 * Private keys are expanded deterministically from (SEED, I) with the RFC 8554
 * Appendix A derivation:  x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED).
 * The per-signature randomizer C, and the SEED / I of HSS child trees, use the same
 * derivation with the reserved indices 0xfffd / 0xfffe / 0xffff (the scheme used by
 * the hash-sigs reference implementation that produced the RFC 9858 test vectors).
 *
 * ############################################################################
 * ##  STATEFUL SIGNATURES — READ THIS BEFORE USING sign()                  ##
 * ##                                                                        ##
 * ##  Every LM-OTS leaf may sign EXACTLY ONE message. Signing two different ##
 * ##  messages with the same leaf (the same q) lets anyone forge.           ##
 * ##                                                                        ##
 * ##  lmsSign() / hssSign() therefore never mutate the key you pass in;     ##
 * ##  they return { signature, nextKey }. The correct protocol is:          ##
 * ##                                                                        ##
 * ##    1. const { signature, nextKey } = hssSign(key, msg)                 ##
 * ##    2. durably persist serializeHssPrivateKey(nextKey)   (fsync!)       ##
 * ##    3. only THEN release `signature` to anyone                          ##
 * ##    4. throw `key` away and use `nextKey` from now on                   ##
 * ##                                                                        ##
 * ##  Within one process, a key state that has already signed is recorded   ##
 * ##  and refuses to sign again. That guard cannot see across processes,    ##
 * ##  restored backups, VM snapshots or copies of the serialized key — the  ##
 * ##  caller owns that problem. A key whose leaves are all used refuses to  ##
 * ##  sign (throws), it never wraps around.                                 ##
 * ############################################################################
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { shake256 } from "@noble/hashes/sha3.js";

// ============================================================================
// Constants
// ============================================================================

/** Length of the I key-pair identifier (independent of the hash function). */
export const I_LEN = 16;

/** Domain-separation constants (RFC 8554 Section 3.1.3 / 7.1). */
const D_PBLC = 0x8080;
const D_MESG = 0x8181;
const D_LEAF = 0x8282;
const D_INTR = 0x8383;

/** Reserved "index" values for the Appendix A style derivation. */
const DERIVE_RANDOMIZER = 0xfffd; // C for leaf q
const DERIVE_CHILD_SEED = 0xfffe; // SEED of the child tree signed by leaf q
const DERIVE_CHILD_I = 0xffff; // I of the child tree signed by leaf q

/** Maximum HSS depth (RFC 8554 Section 6). */
export const HSS_MAX_LEVELS = 8;

// ============================================================================
// Parameter sets
// ============================================================================

export type HashFamily = "sha256" | "shake256";

/** An LM-OTS parameter set (RFC 8554 Table 1, RFC 9858 Table 1). */
export interface LmotsParams {
  readonly name: string;
  readonly type: number; // IANA typecode
  readonly hash: HashFamily;
  readonly n: number; // hash output bytes
  readonly w: number; // Winternitz width in bits
  readonly p: number; // number of n-byte chains
  readonly ls: number; // checksum left shift
}

/** An LMS parameter set (RFC 8554 Table 2, RFC 9858 Table 2). */
export interface LmsParams {
  readonly name: string;
  readonly type: number; // IANA typecode
  readonly hash: HashFamily;
  readonly m: number; // hash output bytes
  readonly h: number; // tree height
}

/** p and ls per (n, w), as tabulated in RFC 8554 Table 1 / RFC 9858 Table 1. */
const P_LS: Record<number, Record<number, [number, number]>> = {
  32: { 1: [265, 7], 2: [133, 6], 4: [67, 4], 8: [34, 0] },
  24: { 1: [200, 8], 2: [101, 6], 4: [51, 4], 8: [26, 0] },
};

/** [name prefix, hash, n, typecode of W1] — W2/W4/W8 follow consecutively. */
const LMOTS_FAMILIES: ReadonlyArray<[string, HashFamily, number, number]> = [
  ["LMOTS_SHA256_N32", "sha256", 32, 0x01],
  ["LMOTS_SHA256_N24", "sha256", 24, 0x05],
  ["LMOTS_SHAKE_N32", "shake256", 32, 0x09],
  ["LMOTS_SHAKE_N24", "shake256", 24, 0x0d],
];

/** [name prefix, hash, m, typecode of H5] — H10/H15/H20/H25 follow consecutively. */
const LMS_FAMILIES: ReadonlyArray<[string, HashFamily, number, number]> = [
  ["LMS_SHA256_M32", "sha256", 32, 0x05],
  ["LMS_SHA256_M24", "sha256", 24, 0x0a],
  ["LMS_SHAKE_M32", "shake256", 32, 0x0f],
  ["LMS_SHAKE_M24", "shake256", 24, 0x14],
];

function buildLmotsTable(): Record<string, LmotsParams> {
  const out: Record<string, LmotsParams> = {};
  for (const [prefix, hash, n, base] of LMOTS_FAMILIES) {
    [1, 2, 4, 8].forEach((w, k) => {
      const [p, ls] = P_LS[n][w];
      const name = `${prefix}_W${w}`;
      out[name] = Object.freeze({ name, type: base + k, hash, n, w, p, ls });
    });
  }
  return Object.freeze(out);
}

function buildLmsTable(): Record<string, LmsParams> {
  const out: Record<string, LmsParams> = {};
  for (const [prefix, hash, m, base] of LMS_FAMILIES) {
    [5, 10, 15, 20, 25].forEach((h, k) => {
      const name = `${prefix}_H${h}`;
      out[name] = Object.freeze({ name, type: base + k, hash, m, h });
    });
  }
  return Object.freeze(out);
}

/** All LM-OTS parameter sets, keyed by RFC name (e.g. "LMOTS_SHAKE_N24_W8"). */
export const LMOTS: Readonly<Record<string, LmotsParams>> = buildLmotsTable();

/** All LMS parameter sets, keyed by RFC name (e.g. "LMS_SHAKE_M24_H5"). */
export const LMS: Readonly<Record<string, LmsParams>> = buildLmsTable();

const LMOTS_BY_TYPE = new Map(Object.values(LMOTS).map((p) => [p.type, p]));
const LMS_BY_TYPE = new Map(Object.values(LMS).map((p) => [p.type, p]));

/** Look up an LM-OTS parameter set by typecode; throws on unknown codes. */
export function lmotsParams(type: number): LmotsParams {
  const p = LMOTS_BY_TYPE.get(type);
  if (!p) throw new Error(`unknown LM-OTS typecode 0x${type.toString(16)}`);
  return p;
}

/** Look up an LMS parameter set by typecode; throws on unknown codes. */
export function lmsParams(type: number): LmsParams {
  const p = LMS_BY_TYPE.get(type);
  if (!p) throw new Error(`unknown LMS typecode 0x${type.toString(16)}`);
  return p;
}

type LmotsRef = LmotsParams | number | string;
type LmsRef = LmsParams | number | string;

function toLmots(r: LmotsRef): LmotsParams {
  if (typeof r === "number") return lmotsParams(r);
  if (typeof r === "string") {
    const p = LMOTS[r];
    if (!p) throw new Error(`unknown LM-OTS parameter set ${r}`);
    return p;
  }
  return lmotsParams(r.type);
}

function toLms(r: LmsRef): LmsParams {
  if (typeof r === "number") return lmsParams(r);
  if (typeof r === "string") {
    const p = LMS[r];
    if (!p) throw new Error(`unknown LMS parameter set ${r}`);
    return p;
  }
  return lmsParams(r.type);
}

// ============================================================================
// Byte utilities
// ============================================================================

function u32str(x: number): Uint8Array {
  return new Uint8Array([(x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff]);
}

function u16str(x: number): Uint8Array {
  return new Uint8Array([(x >>> 8) & 0xff, x & 0xff]);
}

function readU32(buf: Uint8Array, off: number): number {
  if (off + 4 > buf.length) throw new Error("truncated input");
  return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function take(buf: Uint8Array, off: number, len: number): Uint8Array {
  if (off + len > buf.length) throw new Error("truncated input");
  return buf.slice(off, off + len);
}

// ============================================================================
// Hash functions
// ============================================================================

/** H truncated to `len` bytes: SHA-256(/192) or SHAKE256(/256, /192). */
function hash(family: HashFamily, len: number, data: Uint8Array): Uint8Array {
  if (family === "sha256") return sha256(data).slice(0, len);
  return shake256(data, { dkLen: len });
}

/**
 * Appendix A style derivation: H(I || u32str(q) || u16str(j) || u8str(0xff) || SEED).
 * Used for x_q[j] (j < p) and, with reserved j, for C and for HSS child keys.
 */
function derive(family: HashFamily, len: number, I: Uint8Array, q: number, j: number, seed: Uint8Array): Uint8Array {
  return hash(family, len, concat(I, u32str(q), u16str(j), new Uint8Array([0xff]), seed));
}

// ============================================================================
// LM-OTS (RFC 8554 Section 4)
// ============================================================================

/** coef(S, i, w): the i-th w-bit digit of S, most significant first. */
function coef(S: Uint8Array, i: number, w: number): number {
  const byte = S[Math.floor((i * w) / 8)];
  const shift = 8 - (w * (i % (8 / w)) + w);
  return (byte >>> shift) & ((1 << w) - 1);
}

/** Cksm(Q) (Algorithm 2), returned as u16str. */
function checksum(ots: LmotsParams, Q: Uint8Array): Uint8Array {
  const max = (1 << ots.w) - 1;
  let sum = 0;
  for (let i = 0; i < (ots.n * 8) / ots.w; i++) sum += max - coef(Q, i, ots.w);
  return u16str((sum << ots.ls) & 0xffff);
}

/** The p Winternitz digits that drive signing / verification for (I, q, C, msg). */
function messageDigits(ots: LmotsParams, I: Uint8Array, q: number, C: Uint8Array, msg: Uint8Array): number[] {
  const Q = hash(ots.hash, ots.n, concat(I, u32str(q), u16str(D_MESG), C, msg));
  const QC = concat(Q, checksum(ots, Q));
  const digits: number[] = [];
  for (let i = 0; i < ots.p; i++) digits.push(coef(QC, i, ots.w));
  return digits;
}

/**
 * Walk chain i from step `from` up to (but not including) step `to`:
 *   tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)  for j = from .. to-1
 */
function chain(ots: LmotsParams, I: Uint8Array, q: number, i: number, start: Uint8Array, from: number, to: number): Uint8Array {
  // One scratch buffer per chain: prefix stays fixed, only j and tmp change.
  const buf = new Uint8Array(I_LEN + 4 + 2 + 1 + ots.n);
  buf.set(I, 0);
  buf.set(u32str(q), I_LEN);
  buf.set(u16str(i), I_LEN + 4);
  let tmp = start;
  for (let j = from; j < to; j++) {
    buf[I_LEN + 6] = j;
    buf.set(tmp, I_LEN + 7);
    tmp = hash(ots.hash, ots.n, buf);
  }
  return tmp;
}

/** LM-OTS public key hash K for leaf q (Algorithm 1). */
function lmotsPublicHash(ots: LmotsParams, I: Uint8Array, q: number, seed: Uint8Array): Uint8Array {
  const top = (1 << ots.w) - 1;
  const parts: Uint8Array[] = [I, u32str(q), u16str(D_PBLC)];
  for (let i = 0; i < ots.p; i++) {
    const x = derive(ots.hash, ots.n, I, q, i, seed);
    parts.push(chain(ots, I, q, i, x, 0, top));
  }
  return hash(ots.hash, ots.n, concat(...parts));
}

/** A parsed LM-OTS signature. */
export interface LmotsSignature {
  readonly ots: LmotsParams;
  readonly C: Uint8Array;
  readonly y: readonly Uint8Array[];
}

/** LM-OTS sign for leaf q (Algorithm 3), with C derived deterministically. */
function lmotsSign(ots: LmotsParams, I: Uint8Array, q: number, seed: Uint8Array, msg: Uint8Array): LmotsSignature {
  const C = derive(ots.hash, ots.n, I, q, DERIVE_RANDOMIZER, seed);
  const digits = messageDigits(ots, I, q, C, msg);
  const y = digits.map((a, i) => chain(ots, I, q, i, derive(ots.hash, ots.n, I, q, i, seed), 0, a));
  return { ots, C, y };
}

/** Compute the candidate public key Kc from a signature (Algorithm 4b). */
function lmotsCandidate(sig: LmotsSignature, I: Uint8Array, q: number, msg: Uint8Array): Uint8Array {
  const ots = sig.ots;
  const top = (1 << ots.w) - 1;
  const digits = messageDigits(ots, I, q, sig.C, msg);
  const parts: Uint8Array[] = [I, u32str(q), u16str(D_PBLC)];
  digits.forEach((a, i) => parts.push(chain(ots, I, q, i, sig.y[i], a, top)));
  return hash(ots.hash, ots.n, concat(...parts));
}

function encodeLmotsSignature(sig: LmotsSignature): Uint8Array {
  return concat(u32str(sig.ots.type), sig.C, ...sig.y);
}

function decodeLmotsSignatureAt(buf: Uint8Array, off: number): { sig: LmotsSignature; end: number } {
  const ots = lmotsParams(readU32(buf, off));
  off += 4;
  const C = take(buf, off, ots.n);
  off += ots.n;
  const y: Uint8Array[] = [];
  for (let i = 0; i < ots.p; i++, off += ots.n) y.push(take(buf, off, ots.n));
  return { sig: { ots, C, y }, end: off };
}

// ============================================================================
// LMS (RFC 8554 Section 5)
// ============================================================================

/** A parsed LMS public key: u32str(lms type) || u32str(ots type) || I || T[1]. */
export interface LmsPublicKey {
  readonly lms: LmsParams;
  readonly ots: LmotsParams;
  readonly I: Uint8Array;
  readonly root: Uint8Array;
}

/** A parsed LMS signature: u32str(q) || lmots_signature || u32str(type) || path. */
export interface LmsSignature {
  readonly q: number;
  readonly otsSig: LmotsSignature;
  readonly lms: LmsParams;
  readonly path: readonly Uint8Array[];
}

/**
 * LMS private key STATE. Immutable: signing returns a new state with q + 1.
 * `q` is the next unused leaf. `tree` is a cache of the Merkle tree
 * (tree[r] = T[r] for 1 <= r < 2^(h+1)), recomputable from (seed, I).
 */
export interface LmsPrivateKey {
  readonly lms: LmsParams;
  readonly ots: LmotsParams;
  readonly I: Uint8Array;
  readonly seed: Uint8Array;
  readonly q: number;
  readonly tree: readonly Uint8Array[];
}

export interface LmsSignResult {
  /** The signature. Do not release it until `nextKey` is safely persisted. */
  readonly signature: Uint8Array;
  /** The only valid state from now on. Persist it, then discard the old one. */
  readonly nextKey: LmsPrivateKey;
}

/** Key states that have already produced a signature (in-process reuse guard). */
const spentStates = new WeakSet<object>();

/**
 * Build the full Merkle tree. Cost: 2^h LM-OTS public keys, each p * (2^w - 1)
 * hashes — practical up to h = 10..15 in this naive implementation.
 */
function buildTree(lms: LmsParams, ots: LmotsParams, I: Uint8Array, seed: Uint8Array): Uint8Array[] {
  const leaves = 2 ** lms.h;
  const tree: Uint8Array[] = new Array(2 * leaves);
  for (let q = 0; q < leaves; q++) {
    const r = leaves + q;
    const K = lmotsPublicHash(ots, I, q, seed);
    tree[r] = hash(lms.hash, lms.m, concat(I, u32str(r), u16str(D_LEAF), K));
  }
  for (let r = leaves - 1; r >= 1; r--) {
    tree[r] = hash(lms.hash, lms.m, concat(I, u32str(r), u16str(D_INTR), tree[2 * r], tree[2 * r + 1]));
  }
  return tree;
}

function checkSeedAndI(lms: LmsParams, seed: Uint8Array, I: Uint8Array): void {
  if (I.length !== I_LEN) throw new Error(`I must be ${I_LEN} bytes`);
  if (seed.length !== lms.m) throw new Error(`SEED must be ${lms.m} bytes for ${lms.name}`);
}

/**
 * Restore (or create) an LMS private key state at leaf q from (SEED, I).
 * Recomputes the Merkle tree. Use q = 0 for a fresh key.
 */
export function lmsPrivateKeyFromSeed(lmsType: LmsRef, otsType: LmotsRef, seed: Uint8Array, I: Uint8Array, q = 0): LmsPrivateKey {
  const lms = toLms(lmsType);
  const ots = toLmots(otsType);
  checkSeedAndI(lms, seed, I);
  if (!Number.isInteger(q) || q < 0 || q > 2 ** lms.h) throw new Error("q out of range");
  const tree = buildTree(lms, ots, I, seed);
  return Object.freeze({ lms, ots, I: I.slice(), seed: seed.slice(), q, tree: Object.freeze(tree) });
}

/** Generate an LMS key pair deterministically from (SEED, I). */
export function lmsKeyGen(lmsType: LmsRef, otsType: LmotsRef, seed: Uint8Array, I: Uint8Array): { publicKey: Uint8Array; privateKey: LmsPrivateKey } {
  const privateKey = lmsPrivateKeyFromSeed(lmsType, otsType, seed, I, 0);
  return { publicKey: lmsPublicKey(privateKey), privateKey };
}

/** Wire-format LMS public key of a private key. */
export function lmsPublicKey(key: LmsPrivateKey): Uint8Array {
  return encodeLmsPublicKey({ lms: key.lms, ots: key.ots, I: key.I, root: key.tree[1] });
}

/** Number of signatures this state can still produce. */
export function lmsRemaining(key: LmsPrivateKey): number {
  return 2 ** key.lms.h - key.q;
}

/**
 * Sign `msg` with leaf `key.q`. STATEFUL — see the banner at the top of this file.
 * Throws if the key is exhausted or if this exact state object already signed.
 */
export function lmsSign(key: LmsPrivateKey, msg: Uint8Array): LmsSignResult {
  if (spentStates.has(key)) throw new Error("LMS key state already used: sign with the nextKey returned last time");
  if (key.q >= 2 ** key.lms.h) throw new Error("LMS key exhausted: every one-time leaf has been used");
  const { lms, ots, I, seed, q, tree } = key;
  spentStates.add(key);
  const otsSig = lmotsSign(ots, I, q, seed, msg);
  const path: Uint8Array[] = [];
  for (let node = 2 ** lms.h + q, i = 0; i < lms.h; i++, node >>= 1) path.push(tree[node ^ 1]);
  const signature = encodeLmsSignature({ q, otsSig, lms, path });
  const nextKey: LmsPrivateKey = Object.freeze({ lms, ots, I, seed, q: q + 1, tree });
  return Object.freeze({ signature, nextKey });
}

/** Verify an LMS signature (Algorithm 6). Never throws; malformed input -> false. */
export function lmsVerify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): boolean {
  try {
    return lmsVerifyParsed(decodeLmsPublicKey(publicKey), msg, decodeLmsSignature(signature));
  } catch {
    return false;
  }
}

function lmsVerifyParsed(pub: LmsPublicKey, msg: Uint8Array, sig: LmsSignature): boolean {
  if (sig.lms.type !== pub.lms.type || sig.otsSig.ots.type !== pub.ots.type) return false;
  const { lms, I } = pub;
  if (sig.q >= 2 ** lms.h) return false;
  const Kc = lmotsCandidate(sig.otsSig, I, sig.q, msg);
  let node = 2 ** lms.h + sig.q;
  let tmp = hash(lms.hash, lms.m, concat(I, u32str(node), u16str(D_LEAF), Kc));
  for (let i = 0; node > 1; i++, node >>= 1) {
    const pair = node & 1 ? concat(sig.path[i], tmp) : concat(tmp, sig.path[i]);
    tmp = hash(lms.hash, lms.m, concat(I, u32str(node >> 1), u16str(D_INTR), pair));
  }
  return bytesEqual(tmp, pub.root);
}

export function encodeLmsPublicKey(pub: LmsPublicKey): Uint8Array {
  return concat(u32str(pub.lms.type), u32str(pub.ots.type), pub.I, pub.root);
}

function decodeLmsPublicKeyAt(buf: Uint8Array, off: number): { pub: LmsPublicKey; end: number } {
  const lms = lmsParams(readU32(buf, off));
  const ots = lmotsParams(readU32(buf, off + 4));
  const I = take(buf, off + 8, I_LEN);
  const root = take(buf, off + 8 + I_LEN, lms.m);
  return { pub: { lms, ots, I, root }, end: off + 8 + I_LEN + lms.m };
}

/** Parse a wire-format LMS public key (exact length required). */
export function decodeLmsPublicKey(buf: Uint8Array): LmsPublicKey {
  const { pub, end } = decodeLmsPublicKeyAt(buf, 0);
  if (end !== buf.length) throw new Error("trailing bytes after LMS public key");
  return pub;
}

export function encodeLmsSignature(sig: LmsSignature): Uint8Array {
  return concat(u32str(sig.q), encodeLmotsSignature(sig.otsSig), u32str(sig.lms.type), ...sig.path);
}

function decodeLmsSignatureAt(buf: Uint8Array, off: number): { sig: LmsSignature; end: number } {
  const q = readU32(buf, off);
  const ots = decodeLmotsSignatureAt(buf, off + 4);
  off = ots.end;
  const lms = lmsParams(readU32(buf, off));
  off += 4;
  const path: Uint8Array[] = [];
  for (let i = 0; i < lms.h; i++, off += lms.m) path.push(take(buf, off, lms.m));
  return { sig: { q, otsSig: ots.sig, lms, path }, end: off };
}

/** Parse a wire-format LMS signature (exact length required). */
export function decodeLmsSignature(buf: Uint8Array): LmsSignature {
  const { sig, end } = decodeLmsSignatureAt(buf, 0);
  if (end !== buf.length) throw new Error("trailing bytes after LMS signature");
  return sig;
}

/**
 * Serialize an LMS private key state (NOT an RFC format; this file's own):
 *   u32str(lms type) || u32str(ots type) || u32str(q) || I || SEED
 * This is secret material and the authoritative signing state.
 */
export function serializeLmsPrivateKey(key: LmsPrivateKey): Uint8Array {
  return concat(u32str(key.lms.type), u32str(key.ots.type), u32str(key.q), key.I, key.seed);
}

/** Inverse of serializeLmsPrivateKey (recomputes the Merkle tree). */
export function deserializeLmsPrivateKey(buf: Uint8Array): LmsPrivateKey {
  const lms = lmsParams(readU32(buf, 0));
  const ots = lmotsParams(readU32(buf, 4));
  const q = readU32(buf, 8);
  if (buf.length !== 12 + I_LEN + lms.m) throw new Error("bad LMS private key length");
  return lmsPrivateKeyFromSeed(lms, ots, buf.slice(12 + I_LEN), buf.slice(12, 12 + I_LEN), q);
}

// ============================================================================
// HSS (RFC 8554 Section 6)
// ============================================================================

/** Parameter set for one HSS level. */
export interface HssLevelParams {
  readonly lms: LmsRef;
  readonly ots: LmotsRef;
}

/** A parsed HSS public key: u32str(L) || LMS public key of the top tree. */
export interface HssPublicKey {
  readonly levels: number;
  readonly top: LmsPublicKey;
}

/** A parsed HSS signature: u32str(Nspk) || (sig_i || pub_{i+1})* || sig_last. */
export interface HssSignature {
  readonly signedPublicKeys: ReadonlyArray<{ readonly sig: LmsSignature; readonly pub: LmsPublicKey }>;
  readonly sig: LmsSignature;
}

/**
 * HSS private key STATE. Immutable: hssSign returns a new state.
 * keys[0] is the top tree; signedPubKeys[i] = lms_sig_i || pub_{i+1}, the
 * signature by keys[i] (made with its leaf keys[i].q - 1) over keys[i+1]'s public key.
 */
export interface HssPrivateKey {
  readonly keys: readonly LmsPrivateKey[];
  readonly signedPubKeys: readonly Uint8Array[];
}

export interface HssSignResult {
  /** The signature. Do not release it until `nextKey` is safely persisted. */
  readonly signature: Uint8Array;
  /** The only valid state from now on. Persist it, then discard the old one. */
  readonly nextKey: HssPrivateKey;
}

/**
 * SEED and I of the child tree that `parent`'s leaf q will sign. The child's own
 * LMS hash function and size are used, so any parameter sets can be stacked.
 */
function childSeedAndI(parent: LmsPrivateKey, q: number, child: LmsParams): { seed: Uint8Array; I: Uint8Array } {
  const seed = derive(child.hash, child.m, parent.I, q, DERIVE_CHILD_SEED, parent.seed);
  const I = derive(child.hash, child.m, parent.I, q, DERIVE_CHILD_I, parent.seed).slice(0, I_LEN);
  return { seed, I };
}

/**
 * The child LMS key (fresh, q = 0) that `parent`'s next leaf (parent.q) will sign:
 *   SEED' = H(I || u32str(q) || u16str(0xfffe) || u8str(0xff) || SEED)
 *   I'    = first 16 bytes of H(I || u32str(q) || u16str(0xffff) || u8str(0xff) || SEED)
 * (H = the child's LMS hash.) This reproduces the second-level SEED/I of RFC 8554
 * Test Case 2 (parent q = 3).
 */
export function lmsDeriveChildKey(parent: LmsPrivateKey, lmsType: LmsRef, otsType: LmotsRef): LmsPrivateKey {
  const lms = toLms(lmsType);
  const child = childSeedAndI(parent, parent.q, lms);
  return lmsPrivateKeyFromSeed(lms, otsType, child.seed, child.I, 0);
}

/**
 * Build an HSS state from explicit per-level LMS key states (top first).
 * Each parent signs its child's public key with the parent's current leaf, so
 * every parent key passed in is consumed. Used to reproduce RFC 8554 Test Case 2;
 * hssKeyGen is the normal entry point.
 */
export function hssFromLmsKeys(keys: readonly LmsPrivateKey[]): HssPrivateKey {
  if (keys.length < 1 || keys.length > HSS_MAX_LEVELS) throw new Error("HSS needs 1..8 levels");
  const out = [...keys];
  const signedPubKeys: Uint8Array[] = [];
  for (let i = 0; i + 1 < out.length; i++) {
    const childPub = lmsPublicKey(out[i + 1]);
    const { signature, nextKey } = lmsSign(out[i], childPub);
    out[i] = nextKey;
    signedPubKeys.push(concat(signature, childPub));
  }
  return Object.freeze({ keys: Object.freeze(out), signedPubKeys: Object.freeze(signedPubKeys) });
}

/**
 * Generate an HSS key pair deterministically from the top-level (SEED, I).
 * Lower levels are derived from their parent with the reserved 0xfffe/0xffff indices.
 */
export function hssKeyGen(levels: readonly HssLevelParams[], seed: Uint8Array, I: Uint8Array): { publicKey: Uint8Array; privateKey: HssPrivateKey } {
  if (levels.length < 1 || levels.length > HSS_MAX_LEVELS) throw new Error("HSS needs 1..8 levels");
  const keys = [lmsPrivateKeyFromSeed(levels[0].lms, levels[0].ots, seed, I, 0)];
  for (let i = 1; i < levels.length; i++) {
    keys.push(lmsDeriveChildKey(keys[i - 1], levels[i].lms, levels[i].ots));
  }
  const privateKey = hssFromLmsKeys(keys);
  return { publicKey: hssPublicKey(privateKey), privateKey };
}

/** Wire-format HSS public key of a private key. */
export function hssPublicKey(key: HssPrivateKey): Uint8Array {
  return concat(u32str(key.keys.length), lmsPublicKey(key.keys[0]));
}

/**
 * Sign `msg`. STATEFUL — see the banner at the top of this file.
 * When the bottom tree runs out, the deepest parent with leaves left signs a
 * fresh child (derived from its SEED/I/q). Throws when every tree is exhausted
 * or if this exact state object already signed.
 */
export function hssSign(key: HssPrivateKey, msg: Uint8Array): HssSignResult {
  if (spentStates.has(key)) throw new Error("HSS key state already used: sign with the nextKey returned last time");
  const keys = [...key.keys];
  const signedPubKeys = [...key.signedPubKeys];
  const L = keys.length;
  let d = L - 1;
  while (d >= 0 && lmsRemaining(keys[d]) === 0) d--;
  if (d < 0) throw new Error("HSS key exhausted: every one-time leaf has been used");
  spentStates.add(key);
  // Replace every exhausted tree below level d with a fresh child.
  for (let i = d; i + 1 < L; i++) {
    const parent = keys[i];
    const fresh = lmsDeriveChildKey(parent, keys[i + 1].lms, keys[i + 1].ots);
    const freshPub = lmsPublicKey(fresh);
    const { signature, nextKey } = lmsSign(parent, freshPub);
    keys[i] = nextKey;
    keys[i + 1] = fresh;
    signedPubKeys[i] = concat(signature, freshPub);
  }
  const { signature: last, nextKey: lastKey } = lmsSign(keys[L - 1], msg);
  keys[L - 1] = lastKey;
  const signature = concat(u32str(L - 1), ...signedPubKeys, last);
  return Object.freeze({ signature, nextKey: Object.freeze({ keys: Object.freeze(keys), signedPubKeys: Object.freeze(signedPubKeys) }) });
}

/** Verify an HSS signature (Algorithm 6a). Never throws; malformed input -> false. */
export function hssVerify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): boolean {
  try {
    const pub = decodeHssPublicKey(publicKey);
    const sig = decodeHssSignature(signature);
    if (sig.signedPublicKeys.length + 1 !== pub.levels) return false;
    let key = pub.top;
    for (const { sig: s, pub: next } of sig.signedPublicKeys) {
      if (!lmsVerifyParsed(key, encodeLmsPublicKey(next), s)) return false;
      key = next;
    }
    return lmsVerifyParsed(key, msg, sig.sig);
  } catch {
    return false;
  }
}

export function encodeHssPublicKey(pub: HssPublicKey): Uint8Array {
  return concat(u32str(pub.levels), encodeLmsPublicKey(pub.top));
}

/** Parse a wire-format HSS public key (exact length required). */
export function decodeHssPublicKey(buf: Uint8Array): HssPublicKey {
  const levels = readU32(buf, 0);
  if (levels < 1 || levels > HSS_MAX_LEVELS) throw new Error("HSS levels out of range");
  return { levels, top: decodeLmsPublicKey(buf.slice(4)) };
}

export function encodeHssSignature(sig: HssSignature): Uint8Array {
  const parts = sig.signedPublicKeys.flatMap(({ sig: s, pub }) => [encodeLmsSignature(s), encodeLmsPublicKey(pub)]);
  return concat(u32str(sig.signedPublicKeys.length), ...parts, encodeLmsSignature(sig.sig));
}

/** Parse a wire-format HSS signature (exact length required). */
export function decodeHssSignature(buf: Uint8Array): HssSignature {
  const nspk = readU32(buf, 0);
  if (nspk > HSS_MAX_LEVELS - 1) throw new Error("HSS Nspk out of range");
  let off = 4;
  const signedPublicKeys: { sig: LmsSignature; pub: LmsPublicKey }[] = [];
  for (let i = 0; i < nspk; i++) {
    const s = decodeLmsSignatureAt(buf, off);
    const p = decodeLmsPublicKeyAt(buf, s.end);
    signedPublicKeys.push({ sig: s.sig, pub: p.pub });
    off = p.end;
  }
  const last = decodeLmsSignatureAt(buf, off);
  if (last.end !== buf.length) throw new Error("trailing bytes after HSS signature");
  return { signedPublicKeys, sig: last.sig };
}

/**
 * Serialize an HSS private key state (NOT an RFC format; this file's own):
 *   u32str(L) || for each level: u32str(len) || serializeLmsPrivateKey(level)
 * The signed child public keys are regenerated on load: C is deterministic, so
 * re-signing a child key with the same leaf reproduces the identical signature.
 */
export function serializeHssPrivateKey(key: HssPrivateKey): Uint8Array {
  const parts = key.keys.flatMap((k) => {
    const s = serializeLmsPrivateKey(k);
    return [u32str(s.length), s];
  });
  return concat(u32str(key.keys.length), ...parts);
}

/** Inverse of serializeHssPrivateKey. */
export function deserializeHssPrivateKey(buf: Uint8Array): HssPrivateKey {
  const L = readU32(buf, 0);
  if (L < 1 || L > HSS_MAX_LEVELS) throw new Error("HSS levels out of range");
  const keys: LmsPrivateKey[] = [];
  let off = 4;
  for (let i = 0; i < L; i++) {
    const len = readU32(buf, off);
    keys.push(deserializeLmsPrivateKey(take(buf, off + 4, len)));
    off += 4 + len;
  }
  if (off !== buf.length) throw new Error("trailing bytes after HSS private key");
  const signedPubKeys: Uint8Array[] = [];
  for (let i = 0; i + 1 < L; i++) {
    const parent = keys[i];
    if (parent.q < 1) throw new Error("inconsistent HSS state: parent never signed its child");
    // Re-derive the signature parent made with leaf q - 1 (deterministic, same message).
    const rewound = Object.freeze({ ...parent, q: parent.q - 1 });
    const childPub = lmsPublicKey(keys[i + 1]);
    signedPubKeys.push(concat(lmsSign(rewound, childPub).signature, childPub));
  }
  return Object.freeze({ keys: Object.freeze(keys), signedPubKeys: Object.freeze(signedPubKeys) });
}
