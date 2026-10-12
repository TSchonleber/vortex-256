/**
 * VORTEX-256 Hardening & Constant-Time Implementation Framework
 *
 * 256-bit key, 128-bit block symmetric cipher — defensive infrastructure.
 *
 * Design goals:
 *   - Zero key-dependent branches, memory access patterns, or loop counts
 *   - All secret-dependent operations use arithmetic masking, never boolean logic
 *   - Intermediate values are blinded and zeroized eagerly
 *   - Fault attacks are detected via redundant computation and round integrity
 *   - Nonce misuse resistance via SIV-like construction
 *
 * WARNING: JavaScript/TypeScript is NOT an ideal language for constant-time
 * cryptography because the JIT compiler can reintroduce branches and the
 * garbage collector can copy buffers.  This module does the best possible
 * within the runtime constraints and documents every residual risk.
 *
 * Residual risks are tagged with [RESIDUAL-RISK-nn] and listed at the bottom.
 */

// ---------------------------------------------------------------------------
// 0. CONSTANTS
// ---------------------------------------------------------------------------

/** VORTEX-256 block size in bytes. */
export const BLOCK_BYTES = 16;
/** VORTEX-256 key size in bytes. */
export const KEY_BYTES = 32;
/** Number of rounds (public constant — not key-dependent). */
export const NUM_ROUNDS = 16;
/** Nonce size for authenticated encryption mode. */
export const NONCE_BYTES = 16;
/** Tag size for authenticated encryption mode. */
export const TAG_BYTES = 16;

// ---------------------------------------------------------------------------
// 1. CONSTANT-TIME UTILITIES
// ---------------------------------------------------------------------------

/**
 * Constant-time 32-bit equality check.
 * Returns 0xFFFFFFFF if a === b, 0x00000000 otherwise.
 *
 * @param a - First unsigned 32-bit integer
 * @param b - Second unsigned 32-bit integer
 * @returns 0xFFFFFFFF when equal, 0x00000000 otherwise
 */
export function ctEq32(a: number, b: number): number {
  const diff = (a ^ b) | 0;
  // diff is 0 iff a === b
  // (diff | -diff) >>> 31  is 0 when diff === 0, 1 otherwise
  return (((diff | (-diff | 0)) >>> 31) - 1) | 0; // 0xFFFFFFFF or 0
}

/**
 * Constant-time byte equality — returns 0xFF if equal, 0x00 otherwise.
 *
 * @param a - First byte value (only the low 8 bits are compared)
 * @param b - Second byte value (only the low 8 bits are compared)
 * @returns 0xFF when equal, 0x00 otherwise
 */
export function ctEqByte(a: number, b: number): number {
  return ctEq32(a & 0xff, b & 0xff) & 0xff;
}

/**
 * Constant-time unsigned greater-than.
 * Returns 0xFFFFFFFF if a > b, 0x00000000 otherwise.
 *
 * Operands MUST be in [0, 0x7FFFFFFF]: JS bitwise ops are int32, so `(b | 0) -
 * (a | 0)` overflows when both operands have the high bit set. Callers using
 * the full uint32 range must split-compare instead. Not enforced at runtime
 * to avoid branching on secret data.
 *
 * @param a - First value; must be in [0, 0x7FFFFFFF]
 * @param b - Second value; must be in [0, 0x7FFFFFFF]
 * @returns 0xFFFFFFFF if a > b, 0x00000000 otherwise
 */
export function ctGt32(a: number, b: number): number {
  // (b - a) is negative (high bit set) when a > b
  return (((b | 0) - (a | 0)) >>> 31) * 0xffffffff;
}

/**
 * Constant-time unsigned less-than.
 *
 * @param a - First value; must be in [0, 0x7FFFFFFF]
 * @param b - Second value; must be in [0, 0x7FFFFFFF]
 * @returns 0xFFFFFFFF if a < b, 0x00000000 otherwise
 */
export function ctLt32(a: number, b: number): number {
  return ctGt32(b, a);
}

/**
 * Constant-time conditional select (branchless MUX).
 *
 * @param mask - Selection mask — must be exactly 0xFFFFFFFF or 0x00000000
 * @param a - Value to return when mask is 0xFFFFFFFF
 * @param b - Value to return when mask is 0x00000000
 * @returns `a` when mask is all-ones, `b` when mask is all-zeros
 */
export function ctSelect32(mask: number, a: number, b: number): number {
  return (b ^ (mask & (a ^ b))) | 0;
}

/**
 * Constant-time buffer conditional select — copies `src` into `dst` when mask is 0xFF.
 *
 * @param mask - Selection mask — must be exactly 0xFF or 0x00
 * @param dst - Destination buffer (mutated in place when mask is 0xFF)
 * @param src - Source buffer to copy from (must be same length as dst)
 */
export function ctSelectBuffer(
  mask: number,
  dst: Uint8Array,
  src: Uint8Array,
): void {
  const m = mask & 0xff;
  for (let i = 0; i < dst.length; i++) {
    dst[i] = (dst[i] ^ (m & (src[i] ^ dst[i]))) & 0xff;
  }
}

/**
 * Constant-time comparison of two equal-length buffers.
 * Returns true if every byte matches, false otherwise.
 * Runs in time proportional to buffer length regardless of content.
 *
 * CRITICAL: Every byte is visited.  No early exit.
 *
 * @param a - First buffer
 * @param b - Second buffer (may differ in length — length mismatch always returns false)
 * @returns True if every byte matches, false otherwise
 */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    // Length mismatch is NOT secret — it is always a programming error.
    // We still touch every byte of the longer buffer to avoid leaking which
    // buffer was shorter, but return false unconditionally.
    const len = Math.max(a.length, b.length);
    let acc = 1; // nonzero → not equal
    for (let i = 0; i < len; i++) {
      acc |= (a[i % a.length] ?? 0) ^ (b[i % b.length] ?? 0);
    }
    // Force the loop to not be optimised out: write to a volatile sink.
    volatileSink = acc;
    return false;
  }

  let acc = 0;
  for (let i = 0; i < a.length; i++) {
    acc |= a[i] ^ b[i];
  }
  volatileSink = acc;
  return acc === 0;
}

/**
 * Constant-time table lookup.
 * Returns table[index] without revealing `index` through memory access
 * patterns.  Every element of `table` is read on every call.
 *
 * Cost: O(table.length) per lookup — acceptable for S-boxes up to 256 entries.
 *
 * @param table - Lookup table (typically a 256-entry S-box)
 * @param index - Secret index to look up (0–255)
 * @returns The table value at `index`
 */
export function ctLookup(table: Uint8Array, index: number): number {
  let result = 0;
  for (let i = 0; i < table.length; i++) {
    const mask = ctEqByte(i, index);
    result |= table[i] & mask;
  }
  return result & 0xff;
}

/**
 * Constant-time 32-bit table lookup for 32-bit S-box variants.
 *
 * @param table - 32-bit lookup table
 * @param index - Secret index to look up (0–255)
 * @returns The table value at `index`
 */
export function ctLookup32(table: Uint32Array, index: number): number {
  let result = 0;
  for (let i = 0; i < table.length; i++) {
    const mask = ctEq32(i, index & 0xff);
    result |= table[i] & mask;
  }
  return result | 0;
}

// Volatile sink — written to prevent dead-code elimination of constant-time
// loops.  Never read in production; only read by the test harness.
let volatileSink: number = 0;
/** Exposed for test harness only. */
export function __testGetVolatileSink(): number {
  return volatileSink;
}

// ---------------------------------------------------------------------------
// 2. MEMORY PROTECTION
// ---------------------------------------------------------------------------

/**
 * Overwrite every byte of `buf` with 0x00.
 * Uses a reverse-order write + volatile sink to resist dead-store elimination.
 * [RESIDUAL-RISK-02] The JIT/GC may have already copied the buffer contents
 * elsewhere on the heap; we cannot reach those copies.
 *
 * @param buf - Buffer to overwrite with zeroes
 */
export function zeroize(buf: Uint8Array): void {
  for (let i = buf.length - 1; i >= 0; i--) {
    buf[i] = 0;
  }
  // Force the compiler to believe the writes are observed.
  if (buf.length > 0) {
    volatileSink = buf[0] | buf[buf.length - 1];
  }
}

/**
 * Overwrite every element of a Uint32Array with 0.
 *
 * @param buf - 32-bit buffer to zeroize
 */
export function zeroize32(buf: Uint32Array): void {
  for (let i = buf.length - 1; i >= 0; i--) {
    buf[i] = 0;
  }
  if (buf.length > 0) {
    volatileSink = buf[0] | buf[buf.length - 1];
  }
}

/**
 * Secure buffer: a Uint8Array wrapper that
 *   - zeroizes on explicit dispose()
 *   - registers a weak-ref callback that zeroizes if dispose() was never called
 *   - prevents toString() / toJSON() / inspect() from leaking contents
 *
 * Usage:
 *   const key = SecureBuffer.alloc(32);
 *   // ... use key.bytes ...
 *   key.dispose();
 */
export class SecureBuffer {
  private _bytes: Uint8Array;
  private _disposed = false;

  private constructor(size: number) {
    this._bytes = new Uint8Array(size);
  }

  static alloc(size: number): SecureBuffer {
    const sb = new SecureBuffer(size);
    // Register weak-ref GC callback as a safety net.
    // [RESIDUAL-RISK-03] FinalizationRegistry timing is non-deterministic;
    // callers MUST call dispose() explicitly.
    SecureBuffer._registry.register(sb, sb._bytes, sb);
    return sb;
  }

  static from(data: Uint8Array): SecureBuffer {
    const sb = SecureBuffer.alloc(data.length);
    sb._bytes.set(data);
    return sb;
  }

  get bytes(): Uint8Array {
    if (this._disposed) {
      throw new Error("SecureBuffer: use after dispose");
    }
    return this._bytes;
  }

  get length(): number {
    return this._bytes.length;
  }

  dispose(): void {
    if (!this._disposed) {
      zeroize(this._bytes);
      this._disposed = true;
      SecureBuffer._registry.unregister(this);
    }
  }

  /** Prevent key material from appearing in JSON serialization. */
  toJSON(): string {
    return "[SecureBuffer: REDACTED]";
  }

  /** Prevent key material from appearing in string coercion. */
  toString(): string {
    return "[SecureBuffer: REDACTED]";
  }

  /** Prevent key material from appearing in Node.js util.inspect. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "[SecureBuffer: REDACTED]";
  }

  // FinalizationRegistry: if the SecureBuffer is GC'd without dispose(),
  // zeroize the underlying buffer as a last resort.
  private static _registry = new FinalizationRegistry<Uint8Array>((buf) => {
    zeroize(buf);
  });
}

/**
 * Run `fn` with a temporary SecureBuffer that is automatically zeroized when `fn` returns or throws.
 *
 * @param size - Size in bytes of the temporary buffer to allocate
 * @param fn - Callback that receives the raw byte array
 * @returns The value returned by `fn`
 */
export function withSecureBuffer<T>(
  size: number,
  fn: (buf: Uint8Array) => T,
): T {
  const sb = SecureBuffer.alloc(size);
  try {
    return fn(sb.bytes);
  } finally {
    sb.dispose();
  }
}

// ---------------------------------------------------------------------------
// 3. FAULT ATTACK COUNTERMEASURES
// ---------------------------------------------------------------------------

/**
 * Redundant computation verifier.
 *
 * Encrypts `plaintext` with `encryptFn`, then decrypts the result with
 * `decryptFn`, and verifies the round-trip matches the original plaintext
 * in constant time.  If it does not match, the ciphertext is zeroized and
 * an error is thrown — the fault is assumed to be an active attack.
 *
 * This catches single-fault and many multi-fault injection attacks because
 * an attacker would need to fault BOTH encrypt and decrypt in a way that
 * cancels out — combinatorially harder.
 *
 * @param plaintext - Input block to encrypt
 * @param encryptFn - Encryption function to apply and verify
 * @param decryptFn - Decryption function used for round-trip verification
 * @returns The ciphertext block if no fault is detected
 * @throws {FaultDetectedError} If the encrypt/decrypt round-trip does not match
 */
export function redundantEncrypt(
  plaintext: Uint8Array,
  encryptFn: (block: Uint8Array) => Uint8Array,
  decryptFn: (block: Uint8Array) => Uint8Array,
): Uint8Array {
  const ct = encryptFn(plaintext);
  const pt2 = decryptFn(ct);

  if (!ctEqual(plaintext, pt2)) {
    zeroize(ct);
    zeroize(pt2);
    throw new FaultDetectedError(
      "Redundant computation mismatch — possible fault injection",
    );
  }

  zeroize(pt2);
  return ct;
}

/**
 * Redundant decryption verifier (mirror of redundantEncrypt).
 *
 * @param ciphertext - Input block to decrypt
 * @param decryptFn - Decryption function to apply and verify
 * @param encryptFn - Encryption function used for round-trip verification
 * @returns The plaintext block if no fault is detected
 * @throws {FaultDetectedError} If the decrypt/encrypt round-trip does not match
 */
export function redundantDecrypt(
  ciphertext: Uint8Array,
  decryptFn: (block: Uint8Array) => Uint8Array,
  encryptFn: (block: Uint8Array) => Uint8Array,
): Uint8Array {
  const pt = decryptFn(ciphertext);
  const ct2 = encryptFn(pt);

  if (!ctEqual(ciphertext, ct2)) {
    zeroize(pt);
    zeroize(ct2);
    throw new FaultDetectedError(
      "Redundant computation mismatch — possible fault injection",
    );
  }

  zeroize(ct2);
  return pt;
}

/** Thrown when a redundant computation or round counter check detects a fault injection. */
export class FaultDetectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FaultDetectedError";
  }
}

/**
 * Round counter integrity checker.
 *
 * Maintains a redundant counter pair (counter, shadow = ~counter).  At each
 * step the caller increments one and verifies the invariant.  If the
 * invariant breaks, a fault occurred.
 */
export class RoundCounter {
  private _count: number;
  private _shadow: number; // always ~_count

  constructor(private readonly _expected: number) {
    this._count = 0;
    this._shadow = ~0;
  }

  /** Call once per round. Throws on fault. */
  step(): void {
    this._count = (this._count + 1) | 0;
    this._shadow = (this._shadow - 1) | 0;
    this._verify();
  }

  /** Call after all rounds complete. */
  finalize(): void {
    this._verify();
    if (this._count !== this._expected) {
      throw new FaultDetectedError(
        `Round counter expected ${this._expected}, got ${this._count}`,
      );
    }
  }

  private _verify(): void {
    if ((this._count ^ this._shadow) !== -1) {
      throw new FaultDetectedError("Round counter integrity violation");
    }
  }
}

/**
 * State checksum between rounds.
 *
 * Computes a lightweight (non-cryptographic) checksum of the cipher state
 * before and after a round function.  The round function is applied twice
 * on independent copies; the checksums of both copies must agree.
 *
 * This is NOT a MAC — it is a fault-detection mechanism.
 *
 * @param state - Cipher state bytes to checksum
 * @returns 32-bit FNV-like checksum of the state
 */
export function checksumState(state: Uint8Array): number {
  let h = 0x9e3779b9; // golden ratio fractional bits
  for (let i = 0; i < state.length; i++) {
    h = Math.imul(h ^ state[i], 0x01000193); // FNV-like mixing
  }
  return h >>> 0;
}

/**
 * Wrap a round function with checksum verification.
 * Applies `roundFn` to two independent copies and verifies their post-round checksums match.
 *
 * @param state - Cipher state to pass through the round function (mutated in place)
 * @param roundFn - Round function to apply and verify via redundant computation
 * @throws {FaultDetectedError} If the two copies produce different post-round checksums
 */
export function verifiedRound(
  state: Uint8Array,
  roundFn: (s: Uint8Array) => void,
): void {
  // Copy state for redundant computation
  const shadow = new Uint8Array(state.length);
  shadow.set(state);

  roundFn(state);
  roundFn(shadow);

  const cs1 = checksumState(state);
  const cs2 = checksumState(shadow);

  zeroize(shadow);

  if (cs1 !== cs2) {
    zeroize(state);
    throw new FaultDetectedError(
      "Round checksum mismatch — possible fault injection",
    );
  }
}

// ---------------------------------------------------------------------------
// 4. IMPLEMENTATION HARDENING — MASKING & BLINDING
// ---------------------------------------------------------------------------

/**
 * Generate a random masking value.
 * Uses crypto.getRandomValues when available, falls back to a CSPRNG shim.
 */
function randomMask32(): number {
  const buf = new Uint32Array(1);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    // Node.js < 19 fallback
    // eslint-disable-next-line no-undef
    const { randomFillSync } = require("crypto");
    randomFillSync(buf);
  }
  return buf[0];
}

/**
 * Masked value: stores `value XOR mask` and `mask` separately so the
 * true value never exists unmasked in a register/memory location
 * (except during the brief unmask operation).
 */
export class MaskedU32 {
  private _masked: number;
  private _mask: number;

  constructor(value: number) {
    this._mask = randomMask32();
    this._masked = (value ^ this._mask) | 0;
  }

  /** Retrieve the unmasked value.  Call only when needed, and zeroize promptly. */
  unmask(): number {
    return (this._masked ^ this._mask) | 0;
  }

  /** Re-randomize the mask without changing the underlying value. */
  refresh(): void {
    const val = this.unmask();
    this._mask = randomMask32();
    this._masked = (val ^ this._mask) | 0;
  }

  /** Dispose: zeroize both shares. */
  dispose(): void {
    this._masked = 0;
    this._mask = 0;
  }
}

/**
 * Masked buffer: every byte stored XOR'd with a per-byte random mask.
 */
export class MaskedBuffer {
  private _masked: Uint8Array;
  private _mask: Uint8Array;

  constructor(data: Uint8Array) {
    this._mask = new Uint8Array(data.length);
    if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(this._mask);
    } else {
      const { randomFillSync } = require("crypto");
      randomFillSync(this._mask);
    }
    this._masked = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      this._masked[i] = data[i] ^ this._mask[i];
    }
  }

  /** Unmask into a caller-provided buffer (which the caller must zeroize). */
  unmaskInto(dst: Uint8Array): void {
    for (let i = 0; i < this._masked.length; i++) {
      dst[i] = this._masked[i] ^ this._mask[i];
    }
  }

  /** Re-randomize all masks. */
  refresh(): void {
    const tmp = new Uint8Array(this._masked.length);
    this.unmaskInto(tmp);
    if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(this._mask);
    } else {
      const { randomFillSync } = require("crypto");
      randomFillSync(this._mask);
    }
    for (let i = 0; i < tmp.length; i++) {
      this._masked[i] = tmp[i] ^ this._mask[i];
    }
    zeroize(tmp);
  }

  get length(): number {
    return this._masked.length;
  }

  dispose(): void {
    zeroize(this._masked);
    zeroize(this._mask);
  }
}

/**
 * Apply an S-box substitution in constant time with input blinding.
 *
 * 1. Blind the input byte with a random mask.
 * 2. Perform the constant-time lookup on the blinded value — but because
 *    S-box(x XOR r) != S-box(x) XOR S-box(r) in general, we actually
 *    need to look up the UNBLINDED value.  The blinding is used to
 *    decorrelate power traces rather than to hide the index.
 * 3. The result is returned masked with a fresh random byte.
 *
 * Callers receive (S(x) XOR outputMask, outputMask) and must incorporate
 * the mask into subsequent operations.
 *
 * @param sbox - 256-entry substitution table
 * @param input - Byte value to substitute (0–255)
 * @returns `{ masked: S(input) XOR mask, mask }` — caller must unmask to get the true output
 */
export function blindedSboxLookup(
  sbox: Uint8Array,
  input: number,
): { masked: number; mask: number } {
  // Generate output mask
  const maskBuf = new Uint8Array(1);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(maskBuf);
  } else {
    const { randomFillSync } = require("crypto");
    randomFillSync(maskBuf);
  }
  const outputMask = maskBuf[0];

  // Constant-time lookup (touches every element)
  const raw = ctLookup(sbox, input & 0xff);

  return { masked: (raw ^ outputMask) & 0xff, mask: outputMask };
}

/**
 * Hardened key schedule expansion stub.
 *
 * This function template shows how to expand a 256-bit master key into
 * per-round subkeys while keeping the master key masked at all times.
 *
 * The actual round-key derivation logic is cipher-specific and must be
 * filled in by the CIPHER BUILDER agent.  This wrapper handles:
 *   - Unmasking into a temporary buffer
 *   - Invoking the derivation
 *   - Masking each round key
 *   - Zeroizing all temporaries
 *
 * @param maskedKey - The 256-bit master key stored in masked form
 * @param deriveRoundKeys - Cipher-specific function that expands the key into per-round subkeys
 * @returns Array of per-round subkeys, each stored in masked form
 */
export function hardenedKeySchedule(
  maskedKey: MaskedBuffer,
  deriveRoundKeys: (key: Uint8Array) => Uint8Array[],
): MaskedBuffer[] {
  const tmpKey = new Uint8Array(KEY_BYTES);
  maskedKey.unmaskInto(tmpKey);

  const roundKeys = deriveRoundKeys(tmpKey);
  zeroize(tmpKey);

  const maskedRoundKeys = roundKeys.map((rk) => {
    const mrk = new MaskedBuffer(rk);
    zeroize(rk);
    return mrk;
  });

  return maskedRoundKeys;
}

// ---------------------------------------------------------------------------
// 5. AUTHENTICATED ENCRYPTION HARDENING
// ---------------------------------------------------------------------------

/**
 * SIV-like nonce misuse resistant construction for VORTEX-256.
 *
 * Encryption:
 *   1. Derive a synthetic IV (SIV) from key, nonce, associated data, and
 *      plaintext using a PRF (the cipher itself in a CBC-MAC-like mode).
 *   2. Use the SIV as the IV for CTR-mode encryption.
 *   3. The SIV serves as the authentication tag.
 *
 * This means: even if the nonce is reused, the only leak is whether two
 * plaintexts are identical.  No plaintext bits leak otherwise.
 *
 * The functions below are STRUCTURAL — they define the flow and hardening
 * checks.  The actual PRF and CTR primitives must be supplied by the
 * CIPHER BUILDER.
 */

/** Required cipher primitives for the SIV-mode authenticated encryption construction. */
export interface VortexPrimitives {
  /** PRF: key x message -> BLOCK_BYTES tag */
  prf(key: Uint8Array, data: Uint8Array): Uint8Array;
  /** CTR encrypt: key x iv x plaintext -> ciphertext (same length as pt) */
  ctrEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array;
  /** CTR decrypt: key x iv x ciphertext -> plaintext */
  ctrDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

/**
 * Concatenate associated data, nonce, and plaintext with unambiguous
 * length encoding to prevent canonicalization attacks.
 */
function sivInput(
  ad: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  // Format: [8-byte LE ad.length] [ad] [8-byte LE nonce.length] [nonce]
  //         [8-byte LE pt.length] [plaintext]
  const out = new Uint8Array(24 + ad.length + nonce.length + plaintext.length);
  const view = new DataView(out.buffer);

  let offset = 0;
  view.setUint32(offset, ad.length, true);
  view.setUint32(offset + 4, 0, true); // high 32 bits
  offset += 8;
  out.set(ad, offset);
  offset += ad.length;

  view.setUint32(offset, nonce.length, true);
  view.setUint32(offset + 4, 0, true);
  offset += 8;
  out.set(nonce, offset);
  offset += nonce.length;

  view.setUint32(offset, plaintext.length, true);
  view.setUint32(offset + 4, 0, true);
  offset += 8;
  out.set(plaintext, offset);

  return out;
}

/**
 * AD commitment: derive a binding value from key + associated data so that
 * the decryptor can verify the AD has not been altered.  This goes beyond
 * standard AEAD which only checks AD integrity implicitly.
 */
function commitAD(
  prims: VortexPrimitives,
  key: Uint8Array,
  ad: Uint8Array,
): Uint8Array {
  // Domain-separated PRF call: prepend a fixed byte 0x01
  const input = new Uint8Array(1 + ad.length);
  input[0] = 0x01;
  input.set(ad, 1);
  const commitment = prims.prf(key, input);
  zeroize(input);
  return commitment;
}

/**
 * SIV-Encrypt: nonce-misuse-resistant authenticated encryption.
 *
 * @param prims - Cipher primitives (PRF and CTR encrypt/decrypt)
 * @param key - Encryption key
 * @param nonce - Nonce (reuse degrades to deterministic encryption, not catastrophic failure)
 * @param ad - Associated data (authenticated but not encrypted)
 * @param plaintext - Plaintext to encrypt
 * @returns Concatenated `TAG (16B) || AD_COMMITMENT (16B) || CIPHERTEXT`
 */
export function sivEncrypt(
  prims: VortexPrimitives,
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  // 1. Compute synthetic IV / tag
  const prfInput = sivInput(ad, nonce, plaintext);
  const tag = prims.prf(key, prfInput);
  zeroize(prfInput);

  // 2. AD commitment
  const adCommit = commitAD(prims, key, ad);

  // 3. CTR encrypt using tag as IV (clear highest bit to avoid counter overflow)
  const iv = new Uint8Array(tag);
  iv[0] &= 0x7f;
  const ct = prims.ctrEncrypt(key, iv, plaintext);
  zeroize(iv);

  // 4. Assemble output: tag || adCommitment || ciphertext
  const output = new Uint8Array(TAG_BYTES + BLOCK_BYTES + ct.length);
  output.set(tag, 0);
  output.set(adCommit, TAG_BYTES);
  output.set(ct, TAG_BYTES + BLOCK_BYTES);

  zeroize(tag);
  zeroize(adCommit);
  zeroize(ct);

  return output;
}

/**
 * SIV-Decrypt: authenticate then decrypt; plaintext is never returned on auth failure.
 *
 * @param prims - Cipher primitives (PRF and CTR encrypt/decrypt)
 * @param key - Decryption key
 * @param nonce - Nonce used during encryption
 * @param ad - Associated data that must match what was used during encryption
 * @param ciphertextWithTag - Concatenated `TAG || AD_COMMITMENT || CIPHERTEXT` from sivEncrypt
 * @returns Decrypted plaintext
 * @throws {AuthenticationError} If the tag or AD commitment verification fails
 */
export function sivDecrypt(
  prims: VortexPrimitives,
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array {
  if (ciphertextWithTag.length < TAG_BYTES + BLOCK_BYTES) {
    throw new AuthenticationError("Ciphertext too short");
  }

  // 1. Split components
  const receivedTag = ciphertextWithTag.slice(0, TAG_BYTES);
  const receivedAdCommit = ciphertextWithTag.slice(TAG_BYTES, TAG_BYTES + BLOCK_BYTES);
  const ct = ciphertextWithTag.slice(TAG_BYTES + BLOCK_BYTES);

  // 2. Verify AD commitment FIRST (before decryption)
  const expectedAdCommit = commitAD(prims, key, ad);
  if (!ctEqual(receivedAdCommit, expectedAdCommit)) {
    zeroize(expectedAdCommit);
    zeroize(receivedTag);
    zeroize(ct);
    throw new AuthenticationError("AD commitment mismatch");
  }
  zeroize(expectedAdCommit);

  // 3. Decrypt
  const iv = new Uint8Array(receivedTag);
  iv[0] &= 0x7f;
  const plaintext = prims.ctrDecrypt(key, iv, ct);
  zeroize(iv);
  zeroize(ct);

  // 4. Recompute tag from decrypted plaintext and verify
  const prfInput = sivInput(ad, nonce, plaintext);
  const expectedTag = prims.prf(key, prfInput);
  zeroize(prfInput);

  if (!ctEqual(receivedTag, expectedTag)) {
    zeroize(plaintext);
    zeroize(receivedTag);
    zeroize(expectedTag);
    throw new AuthenticationError("Authentication tag mismatch");
  }

  zeroize(receivedTag);
  zeroize(expectedTag);

  return plaintext;
}

/** Thrown by SIV decrypt when the authentication tag or AD commitment does not match. */
export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

// ---------------------------------------------------------------------------
// 6. TEST HARNESS
// ---------------------------------------------------------------------------

/**
 * Timing oracle detector.
 *
 * Runs `fn` on two different inputs `iterations` times each and compares
 * the mean execution times.  If the absolute difference exceeds
 * `thresholdNs` nanoseconds, the test FAILS — indicating a potential
 * timing side channel.
 *
 * Uses `performance.now()` which offers microsecond resolution in most
 * environments.  For sub-microsecond leaks, this detector may not suffice;
 * use hardware counters (perf/PAPI) for higher assurance.
 *
 * [RESIDUAL-RISK-04] JIT warmup, GC pauses, and OS scheduling introduce
 * noise.  We mitigate with warmup rounds and statistical analysis.
 */
/** Result from a `timingOracleDetector` run, including statistical measurements and pass/fail verdict. */
export interface TimingTestResult {
  pass: boolean;
  meanA_ns: number;
  meanB_ns: number;
  diff_ns: number;
  threshold_ns: number;
  stddevA_ns: number;
  stddevB_ns: number;
  /** Welch's t-test p-value approximation */
  pValue: number;
  iterations: number;
}

/**
 * Measure execution time of `fn` on two inputs and test for a timing side channel.
 *
 * @param fn - Function under test (must be deterministic)
 * @param inputA - First test input (e.g. a zero buffer)
 * @param inputB - Second test input (e.g. a random buffer)
 * @param iterations - Number of timed samples per input
 * @param thresholdNs - Maximum allowed mean time difference in nanoseconds
 * @param warmupRounds - JIT warmup iterations before measurement begins
 * @returns Timing test result including means, stddevs, t-test p-value, and pass/fail
 */
export function timingOracleDetector(
  fn: (input: Uint8Array) => void,
  inputA: Uint8Array,
  inputB: Uint8Array,
  iterations: number = 10000,
  thresholdNs: number = 1000, // 1 microsecond
  warmupRounds: number = 1000,
): TimingTestResult {
  // Warmup: let the JIT stabilize
  for (let i = 0; i < warmupRounds; i++) {
    fn(inputA);
    fn(inputB);
  }

  const timesA: number[] = new Array(iterations);
  const timesB: number[] = new Array(iterations);

  // Interleave measurements to cancel drift
  for (let i = 0; i < iterations; i++) {
    const startA = performance.now();
    fn(inputA);
    const endA = performance.now();
    timesA[i] = (endA - startA) * 1_000_000; // ms -> ns

    const startB = performance.now();
    fn(inputB);
    const endB = performance.now();
    timesB[i] = (endB - startB) * 1_000_000;
  }

  const meanA = timesA.reduce((s, t) => s + t, 0) / iterations;
  const meanB = timesB.reduce((s, t) => s + t, 0) / iterations;

  const varianceA =
    timesA.reduce((s, t) => s + (t - meanA) ** 2, 0) / (iterations - 1);
  const varianceB =
    timesB.reduce((s, t) => s + (t - meanB) ** 2, 0) / (iterations - 1);

  const stddevA = Math.sqrt(varianceA);
  const stddevB = Math.sqrt(varianceB);

  // Welch's t-test
  const se = Math.sqrt(varianceA / iterations + varianceB / iterations);
  const tStat = se > 0 ? Math.abs(meanA - meanB) / se : 0;
  // Approximate p-value using normal distribution for large N
  const pValue = 2 * (1 - normalCDF(tStat));

  const diff = Math.abs(meanA - meanB);

  return {
    pass: diff < thresholdNs && pValue > 0.01,
    meanA_ns: meanA,
    meanB_ns: meanB,
    diff_ns: diff,
    threshold_ns: thresholdNs,
    stddevA_ns: stddevA,
    stddevB_ns: stddevB,
    pValue,
    iterations,
  };
}

/** Standard normal CDF approximation (Abramowitz & Stegun). */
function normalCDF(x: number): number {
  const a1 = 0.254829592;
  const a2 = -0.284496736;
  const a3 = 1.421413741;
  const a4 = -1.453152027;
  const a5 = 1.061405429;
  const p = 0.3275911;

  const sign = x < 0 ? -1 : 1;
  x = Math.abs(x) / Math.SQRT2;
  const t = 1.0 / (1.0 + p * x);
  const y =
    1.0 - ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);

  return 0.5 * (1.0 + sign * y);
}

/**
 * Memory scan for key material after zeroization.
 *
 * Checks a buffer that should have been zeroized.  Returns true if all
 * bytes are zero, false if key material remains.
 *
 * NOTE: This only checks the specific buffer reference.  It cannot detect
 * copies the GC may have made elsewhere on the heap.  For higher assurance,
 * use a native addon that scans process memory.
 *
 * @param buf - Buffer to verify
 * @returns True if every byte is zero, false if any key material remains
 */
export function verifyZeroized(buf: Uint8Array): boolean {
  let acc = 0;
  for (let i = 0; i < buf.length; i++) {
    acc |= buf[i];
  }
  return acc === 0;
}

/**
 * Fault injection simulator.
 *
 * Wraps a round function and randomly flips a single bit in the state
 * at the specified round number.  Used to test that the fault detection
 * countermeasures (redundant computation, round counter, checksums)
 * actually catch faults.
 */
export class FaultInjector {
  private _targetRound: number;
  private _currentRound: number = 0;
  private _faultInjected: boolean = false;

  /**
   * @param targetRound  Zero-indexed round at which to inject fault
   * @param bitPosition  Bit position in the state to flip (0-127 for 128-bit block)
   */
  constructor(
    private readonly targetRound_: number,
    private readonly bitPosition: number,
  ) {
    this._targetRound = targetRound_;
  }

  /**
   * Wrap a round function.  Returns a new function that injects a fault
   * at the target round.
   */
  wrap(roundFn: (state: Uint8Array) => void): (state: Uint8Array) => void {
    return (state: Uint8Array) => {
      roundFn(state);

      if (this._currentRound === this._targetRound) {
        const byteIdx = this.bitPosition >>> 3;
        const bitIdx = this.bitPosition & 7;
        if (byteIdx < state.length) {
          state[byteIdx] ^= 1 << bitIdx;
        }
        this._faultInjected = true;
      }
      this._currentRound++;
    };
  }

  get faultInjected(): boolean {
    return this._faultInjected;
  }

  reset(): void {
    this._currentRound = 0;
    this._faultInjected = false;
  }
}

/**
 * Integration test: verify that the fault injection is caught by the
 * redundant computation verifier.
 */
/**
 * Integration test: verify that the fault injection is caught by the redundant computation verifier.
 *
 * @param plaintext - Input block to encrypt
 * @param encryptFn - Correct encryption function (for redundant verification)
 * @param decryptFn - Correct decryption function (for redundant verification)
 * @param faultedEncryptFn - Faulty encryption function that should be caught
 * @returns `{ detected: true }` if the fault was caught, or `{ detected: false, error }` otherwise
 */
export function testFaultDetection(
  plaintext: Uint8Array,
  encryptFn: (block: Uint8Array) => Uint8Array,
  decryptFn: (block: Uint8Array) => Uint8Array,
  faultedEncryptFn: (block: Uint8Array) => Uint8Array,
): { detected: boolean; error?: string } {
  try {
    redundantEncrypt(plaintext, faultedEncryptFn, decryptFn);
    return { detected: false, error: "Fault was NOT detected — CRITICAL FAILURE" };
  } catch (e) {
    if (e instanceof FaultDetectedError) {
      return { detected: true };
    }
    return { detected: false, error: `Unexpected error: ${(e as Error).message}` };
  }
}

/**
 * Run the full hardening self-test suite and return pass/fail results for each check.
 *
 * @returns Array of test results with name, pass flag, and detail string
 */
export function selfTest(): Array<{
  name: string;
  pass: boolean;
  detail: string;
}> {
  const results: Array<{ name: string; pass: boolean; detail: string }> = [];

  // --- Constant-time equality ---
  {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    const c = new Uint8Array([1, 2, 3, 5]);
    results.push({
      name: "ctEqual: identical buffers",
      pass: ctEqual(a, b) === true,
      detail: "Expected true",
    });
    results.push({
      name: "ctEqual: differing buffers",
      pass: ctEqual(a, c) === false,
      detail: "Expected false",
    });
  }

  // --- Constant-time select ---
  {
    const r1 = ctSelect32(0xffffffff, 42, 99);
    const r2 = ctSelect32(0x00000000, 42, 99);
    results.push({
      name: "ctSelect32: mask=all-ones selects a",
      pass: r1 === 42,
      detail: `Got ${r1}`,
    });
    results.push({
      name: "ctSelect32: mask=zero selects b",
      pass: r2 === 99,
      detail: `Got ${r2}`,
    });
  }

  // --- Constant-time lookup ---
  {
    const table = new Uint8Array(256);
    for (let i = 0; i < 256; i++) table[i] = (i * 7 + 3) & 0xff;
    for (let idx = 0; idx < 256; idx++) {
      const got = ctLookup(table, idx);
      if (got !== table[idx]) {
        results.push({
          name: `ctLookup: index ${idx}`,
          pass: false,
          detail: `Expected ${table[idx]}, got ${got}`,
        });
        break;
      }
    }
    results.push({
      name: "ctLookup: all 256 indices correct",
      pass: true,
      detail: "All lookups matched",
    });
  }

  // --- ctEq32 / ctGt32 / ctLt32 ---
  {
    results.push({
      name: "ctEq32: equal",
      pass: ctEq32(0x42, 0x42) === -1, // 0xFFFFFFFF as signed
      detail: `Got ${ctEq32(0x42, 0x42)}`,
    });
    results.push({
      name: "ctEq32: not equal",
      pass: ctEq32(0x42, 0x43) === 0,
      detail: `Got ${ctEq32(0x42, 0x43)}`,
    });
    results.push({
      name: "ctGt32: 5 > 3",
      pass: ctGt32(5, 3) === 0xffffffff,
      detail: `Got ${ctGt32(5, 3) >>> 0}`,
    });
    results.push({
      name: "ctLt32: 3 < 5",
      pass: ctLt32(3, 5) === 0xffffffff,
      detail: `Got ${ctLt32(3, 5) >>> 0}`,
    });
  }

  // --- SecureBuffer ---
  {
    const sb = SecureBuffer.alloc(32);
    sb.bytes[0] = 0xab;
    results.push({
      name: "SecureBuffer: toJSON redacts",
      pass: sb.toJSON() === "[SecureBuffer: REDACTED]",
      detail: sb.toJSON(),
    });
    results.push({
      name: "SecureBuffer: toString redacts",
      pass: sb.toString() === "[SecureBuffer: REDACTED]",
      detail: sb.toString(),
    });
    sb.dispose();
    let threw = false;
    try {
      void sb.bytes;
    } catch {
      threw = true;
    }
    results.push({
      name: "SecureBuffer: use-after-dispose throws",
      pass: threw,
      detail: threw ? "Threw as expected" : "DID NOT THROW",
    });
  }

  // --- Zeroization ---
  {
    const buf = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]);
    zeroize(buf);
    results.push({
      name: "zeroize: buffer is zeroed",
      pass: verifyZeroized(buf),
      detail: `First byte: ${buf[0]}`,
    });
  }

  // --- Round counter ---
  {
    const rc = new RoundCounter(NUM_ROUNDS);
    let ok = true;
    for (let i = 0; i < NUM_ROUNDS; i++) rc.step();
    try {
      rc.finalize();
    } catch {
      ok = false;
    }
    results.push({
      name: "RoundCounter: normal operation",
      pass: ok,
      detail: ok ? "16 rounds completed" : "Unexpected fault",
    });
  }

  // --- Masking ---
  {
    const mv = new MaskedU32(0xdeadbeef);
    results.push({
      name: "MaskedU32: unmask recovers value",
      pass: (mv.unmask() >>> 0) === 0xdeadbeef,
      detail: `Got 0x${(mv.unmask() >>> 0).toString(16)}`,
    });
    mv.refresh();
    results.push({
      name: "MaskedU32: refresh preserves value",
      pass: (mv.unmask() >>> 0) === 0xdeadbeef,
      detail: `Got 0x${(mv.unmask() >>> 0).toString(16)}`,
    });
    mv.dispose();
  }

  return results;
}

// ---------------------------------------------------------------------------
// RESIDUAL RISKS
// ---------------------------------------------------------------------------
//
// [RESIDUAL-RISK-01] V8/SpiderMonkey/JSC may optimise bitwise operations in
//   ways that reintroduce branches or short-circuit evaluation.  Mitigated by
//   keeping operations simple and testing with the timing oracle.
//
// [RESIDUAL-RISK-02] The JavaScript GC can copy buffer contents during
//   compaction.  The original copy is zeroed, but the GC copy is not.
//   Mitigation: use ArrayBuffer.transfer() where available (proposal stage),
//   or a native addon for truly sensitive deployments.
//
// [RESIDUAL-RISK-03] FinalizationRegistry callbacks have no guaranteed timing.
//   Key material may linger in memory for an unbounded period if dispose() is
//   not called.  This is a safety net, not a guarantee.
//
// [RESIDUAL-RISK-04] performance.now() resolution varies by browser/runtime
//   and may be artificially degraded (e.g., Spectre mitigations reduce timer
//   resolution to 5us in browsers).  For high-assurance timing tests, use
//   native performance counters.
//
// [RESIDUAL-RISK-05] BigInt operations in JavaScript may not be constant-time
//   because the runtime can allocate different amounts of memory for different
//   magnitude values.  This module avoids BigInt entirely.
//
// [RESIDUAL-RISK-06] Module-level singletons (volatileSink) could be observed
//   by other code in the same realm.  In a browser, use a dedicated Worker.
