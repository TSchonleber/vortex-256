/**
 * VORTEX-PQ v1 — hybrid post-quantum public-key encryption.
 *
 * ML-KEM-1024 + X25519 hybrid KEM, HKDF-SHA3-512, key commitment, and a cascade of
 * VORTEX-256-AEAD inside XChaCha20-Poly1305. The normative description is docs/SPEC.md;
 * keep this file and rust/src/pq.rs in lockstep with it.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha3_256, sha3_512, shake256 } from "@noble/hashes/sha3.js";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { aeadDecrypt, aeadEncrypt } from "../vortex-cipher";

// ============================================================================
// Constants
// ============================================================================

const LABEL = ascii("VORTEX-PQ-v1");
const MAGIC = ascii("VXPQ");
const VERSION = 0x01;
const SUITE_MLKEM1024_X25519 = 0x01;

export const SEED_SIZE = 32;
export const ESEED_SIZE = 64;
const MLKEM_PK = 1568;
const MLKEM_CT = 1568;
const X25519_LEN = 32;
export const PUBLIC_KEY_SIZE = MLKEM_PK + X25519_LEN; // 1600
export const KEM_CIPHERTEXT_SIZE = MLKEM_CT + X25519_LEN; // 1600
const HEADER_SIZE = 6;
const COMMIT_SIZE = 32;
const TAG_SIZE = 16;
export const OVERHEAD = HEADER_SIZE + KEM_CIPHERTEXT_SIZE + COMMIT_SIZE + 2 * TAG_SIZE; // 1670

/** Single error for every decryption failure, so callers can't learn which layer rejected. */
export class OpenError extends Error {
  constructor() {
    super("VORTEX-PQ: envelope could not be opened");
    this.name = "OpenError";
  }
}

// ============================================================================
// Key generation
// ============================================================================

interface ExpandedKey {
  mlkemSecret: Uint8Array;
  mlkemPublic: Uint8Array;
  x25519Secret: Uint8Array;
  x25519Public: Uint8Array;
}

function expandSeed(seed: Uint8Array): ExpandedKey {
  if (seed.length !== SEED_SIZE) throw new Error(`VORTEX-PQ: seed must be ${SEED_SIZE} bytes`);
  const e = shake256(concatBytes(LABEL, ascii("/keygen"), seed), { dkLen: 96 });
  // noble's ML-KEM keygen seed is d || z, matching FIPS 203 KeyGen_internal(d, z).
  const { secretKey, publicKey } = ml_kem1024.keygen(e.subarray(0, 64));
  const x25519Secret = e.slice(64, 96);
  return { mlkemSecret: secretKey, mlkemPublic: publicKey, x25519Secret, x25519Public: x25519.getPublicKey(x25519Secret) };
}

/** Derives the 1600-byte public key for a 32-byte secret seed. */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  const k = expandSeed(seed);
  return concatBytes(k.mlkemPublic, k.x25519Public);
}

/** Generates a fresh key pair. The secret key is the 32-byte seed. */
export function generateKeyPair(seed: Uint8Array = randomBytes(SEED_SIZE)): { secretKey: Uint8Array; publicKey: Uint8Array } {
  return { secretKey: seed.slice(), publicKey: publicKeyFromSeed(seed) };
}

// ============================================================================
// Hybrid KEM
// ============================================================================

function combine(ssM: Uint8Array, ssX: Uint8Array, ctM: Uint8Array, ctX: Uint8Array, pkM: Uint8Array, pkX: Uint8Array): Uint8Array {
  return sha3_512(concatBytes(LABEL, ascii("/combine"), ssM, ssX, ctX, pkX, sha3_256(ctM), sha3_256(pkM)));
}

/** X25519 that rejects low-order points (all-zero shared secret). noble throws on them already. */
function dh(secret: Uint8Array, pub: Uint8Array): Uint8Array {
  const s = x25519.getSharedSecret(secret, pub);
  if (s.every((b) => b === 0)) throw new Error("VORTEX-PQ: X25519 produced an all-zero shared secret");
  return s;
}

export function encapsulate(publicKey: Uint8Array, eseed: Uint8Array = randomBytes(ESEED_SIZE)): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  if (publicKey.length !== PUBLIC_KEY_SIZE) throw new Error(`VORTEX-PQ: public key must be ${PUBLIC_KEY_SIZE} bytes`);
  if (eseed.length !== ESEED_SIZE) throw new Error(`VORTEX-PQ: eseed must be ${ESEED_SIZE} bytes`);
  const pkM = publicKey.subarray(0, MLKEM_PK);
  const pkX = publicKey.subarray(MLKEM_PK);
  const { cipherText: ctM, sharedSecret: ssM } = ml_kem1024.encapsulate(pkM, eseed.subarray(0, 32));
  const ek = eseed.subarray(32, 64);
  const ctX = x25519.getPublicKey(ek);
  const ssX = dh(ek, pkX);
  return { ciphertext: concatBytes(ctM, ctX), sharedSecret: combine(ssM, ssX, ctM, ctX, pkM, pkX) };
}

export function decapsulate(seed: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length !== KEM_CIPHERTEXT_SIZE) throw new Error(`VORTEX-PQ: KEM ciphertext must be ${KEM_CIPHERTEXT_SIZE} bytes`);
  const k = expandSeed(seed);
  const ctM = ciphertext.subarray(0, MLKEM_CT);
  const ctX = ciphertext.subarray(MLKEM_CT);
  const ssM = ml_kem1024.decapsulate(ctM, k.mlkemSecret);
  const ssX = dh(k.x25519Secret, ctX);
  return combine(ssM, ssX, ctM, ctX, k.mlkemPublic, k.x25519Public);
}

// ============================================================================
// Envelope
// ============================================================================

export interface MessageKeys {
  th: Uint8Array;
  k1: Uint8Array;
  n1: Uint8Array;
  k2: Uint8Array;
  n2: Uint8Array;
  commit: Uint8Array;
}

/** HKDF-SHA3-512 key schedule shared by every VORTEX-PQ suite (docs/SPEC.md). */
export function deriveMessageKeys(ikm: Uint8Array, th: Uint8Array): MessageKeys {
  const okm = hkdf(sha3_512, ikm, LABEL, th, 132);
  return {
    th,
    k1: okm.slice(0, 32),
    n1: okm.slice(32, 44),
    k2: okm.slice(44, 76),
    n2: okm.slice(76, 100),
    commit: okm.slice(100, 132),
  };
}

/** VORTEX-256-AEAD inside XChaCha20-Poly1305, both bound to th || aad. Returns commit || outer. */
export function cascadeEncrypt(k: MessageKeys, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const ad = concatBytes(k.th, aad);
  const v = aeadEncrypt(k.k1, k.n1, plaintext, ad);
  const outer = xchacha20poly1305(k.k2, k.n2, ad).encrypt(concatBytes(v.ciphertext, v.tag));
  return concatBytes(k.commit, outer);
}

/** Inverse of cascadeEncrypt. Throws OpenError on any failure, checking the commitment first. */
export function cascadeDecrypt(k: MessageKeys, body: Uint8Array, aad: Uint8Array): Uint8Array {
  if (body.length < COMMIT_SIZE + 2 * TAG_SIZE) throw new OpenError();
  if (!bytesEqual(body.subarray(0, COMMIT_SIZE), k.commit)) throw new OpenError();
  try {
    const ad = concatBytes(k.th, aad);
    const inner = xchacha20poly1305(k.k2, k.n2, ad).decrypt(body.subarray(COMMIT_SIZE));
    const pt = aeadDecrypt(k.k1, k.n1, inner.subarray(0, inner.length - TAG_SIZE), inner.subarray(inner.length - TAG_SIZE), ad);
    if (pt === null) throw new OpenError();
    return pt;
  } catch {
    throw new OpenError();
  }
}

/**
 * Encrypts `plaintext` to `publicKey`. `aad` is authenticated but not encrypted, and must be
 * supplied again to open. `eseed` exists for test vectors only; leave it to the default CSPRNG.
 */
export function seal(
  publicKey: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  eseed: Uint8Array = randomBytes(ESEED_SIZE)
): Uint8Array {
  const header = Uint8Array.of(...MAGIC, VERSION, SUITE_MLKEM1024_X25519);
  const { ciphertext: kemCt, sharedSecret } = encapsulate(publicKey, eseed);
  const k = deriveMessageKeys(sharedSecret, sha3_512(concatBytes(header, kemCt, publicKey)));
  return concatBytes(header, kemCt, cascadeEncrypt(k, plaintext, aad));
}

/** Decrypts an envelope with the recipient's 32-byte seed. Throws `OpenError` on any failure. */
export function open(seed: Uint8Array, envelope: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
  if (envelope.length < OVERHEAD) throw new OpenError();
  const header = envelope.subarray(0, HEADER_SIZE);
  if (!bytesEqual(header.subarray(0, 4), MAGIC) || header[4] !== VERSION || header[5] !== SUITE_MLKEM1024_X25519) {
    throw new OpenError();
  }
  const kemCt = envelope.subarray(HEADER_SIZE, HEADER_SIZE + KEM_CIPHERTEXT_SIZE);
  let k: MessageKeys;
  try {
    const ss = decapsulate(seed, kemCt);
    k = deriveMessageKeys(ss, sha3_512(concatBytes(header, kemCt, publicKeyFromSeed(seed))));
  } catch {
    throw new OpenError();
  }
  return cascadeDecrypt(k, envelope.subarray(HEADER_SIZE + KEM_CIPHERTEXT_SIZE), aad);
}

// ============================================================================
// Helpers
// ============================================================================

export function ascii(s: string): Uint8Array {
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

/** Constant-time for equal lengths. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

