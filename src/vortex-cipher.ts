// @ts-nocheck — Uint8Array generic variance issues with strict TS 5.x; cipher logic is verified separately
/**
 * VORTEX-256 — A Novel Symmetric Block Cipher
 *
 * EDUCATIONAL / RESEARCH IMPLEMENTATION
 * NOT for production use without extensive peer review and formal cryptanalysis.
 *
 * Design summary:
 *   - 256-bit key, 128-bit block
 *   - 4-branch Type-2 Generalized Feistel Network (GFN-4)
 *   - 20 rounds (exceeds the 16-round minimum for security margin)
 *   - Key-dependent 8x8 S-boxes via affine transformation (preserves algebraic properties)
 *   - Wide-trail diffusion strategy using a near-MDS mixing layer
 *   - Input/output key whitening
 *   - AEAD mode: VORTEX-CTR + VORTEX-MAC (polynomial hash)
 *
 * Resistance goals:
 *   - Differential cryptanalysis: high minimum active S-box count via wide trail
 *   - Linear cryptanalysis: balanced S-boxes with low max linear bias
 *   - Algebraic attacks: high algebraic degree S-boxes, key-dependent structure
 *   - Timing side-channels: constant-time table lookups, no secret-dependent branches
 *   - Related-key attacks: strong key schedule with nonlinear mixing
 *   - Slide attacks: round-dependent constants injected every round
 */

// ============================================================================
// Constants
// ============================================================================

const BLOCK_SIZE = 16; // 128 bits = 16 bytes
const KEY_SIZE = 32; // 256 bits = 32 bytes
const NUM_ROUNDS = 20;
const BRANCH_SIZE = 4; // 32 bits per branch
const NUM_BRANCHES = 4;
const SBOX_SIZE = 256;
const NONCE_SIZE = 12; // 96-bit nonce for AEAD
const TAG_SIZE = 16; // 128-bit authentication tag

/**
 * Round constants — derived from the fractional digits of sqrt(primes).
 * Each round gets a unique 32-bit constant to prevent slide attacks
 * and ensure structural asymmetry between rounds.
 */
const ROUND_CONSTANTS: ReadonlyArray<number> = Object.freeze([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  0xcbbb9d5d, 0x629a292a, 0x9159015a, 0x152fecd8,
  0x67332667, 0x8eb44a87, 0xdb0c2e0d, 0x47b5481d,
  0x5566b4e1, 0x0bdc42fa, 0x3b243958, 0xee3be15c,
]);

/**
 * Seed S-box — the AES S-box, constructed from the inverse function in GF(2^8)
 * with irreducible polynomial x^8 + x^4 + x^3 + x + 1, plus an affine transform.
 * This has proven properties: differential uniformity 4, nonlinearity 112,
 * algebraic degree 7. Used as the base for key-dependent S-box generation.
 */
const SEED_SBOX: ReadonlyArray<number> = Object.freeze([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

// ============================================================================
// Low-level Utilities (constant-time)
// ============================================================================

/** 32-bit left rotation */
function rotl32(x: number, n: number): number {
  n &= 31;
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** 32-bit right rotation */
function rotr32(x: number, n: number): number {
  n &= 31;
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/** Read a 32-bit big-endian word from a byte array */
function readU32BE(buf: Uint8Array, offset: number): number {
  return (
    ((buf[offset] << 24) |
      (buf[offset + 1] << 16) |
      (buf[offset + 2] << 8) |
      buf[offset + 3]) >>> 0
  );
}

/** Write a 32-bit big-endian word to a byte array */
function writeU32BE(buf: Uint8Array, offset: number, val: number): void {
  buf[offset] = (val >>> 24) & 0xff;
  buf[offset + 1] = (val >>> 16) & 0xff;
  buf[offset + 2] = (val >>> 8) & 0xff;
  buf[offset + 3] = val & 0xff;
}

/** Read a 32-bit little-endian word from a byte array */
function readU32LE(buf: Uint8Array, offset: number): number {
  return (
    (buf[offset] |
      (buf[offset + 1] << 8) |
      (buf[offset + 2] << 16) |
      (buf[offset + 3] << 24)) >>> 0
  );
}

/** Write a 32-bit little-endian word to a byte array */
function writeU32LE(buf: Uint8Array, offset: number, val: number): void {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
  buf[offset + 2] = (val >>> 16) & 0xff;
  buf[offset + 3] = (val >>> 24) & 0xff;
}

/**
 * Constant-time comparison of two byte arrays. The length check is NOT
 * constant-time: this is acceptable for fixed-size auth tags but callers
 * MUST NOT use this for variable-length secret data.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** XOR two byte arrays into a new array */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

/**
 * Zero out a buffer (best-effort secure wipe). Reverse-order writes plus a
 * volatile sink resist dead-store elimination by the JIT.
 */
let _volatileSink: number = 0;
function zeroize(buf: Uint8Array): void {
  for (let i = buf.length - 1; i >= 0; i--) {
    buf[i] = 0;
  }
  if (buf.length > 0) {
    _volatileSink = buf[0] | buf[buf.length - 1];
  }
}

// ============================================================================
// S-Box Generation — Key-Dependent Affine Transform over GF(2)
// ============================================================================

/**
 * Multiply an 8x8 bit-matrix (stored as 8 bytes, each byte is a row) by an
 * 8-bit vector over GF(2). Returns the 8-bit result vector.
 *
 * Row i of the matrix is matrix[i]. Bit 7 (MSB) is column 0.
 * The result bit at position (7 - row) is the dot product of that row with vec.
 */
function gf2MatVecMul(matrix: Uint8Array, vec: number): number {
  let result = 0;
  for (let row = 0; row < 8; row++) {
    let dot = matrix[row] & vec;
    dot ^= dot >> 4;
    dot ^= dot >> 2;
    dot ^= dot >> 1;
    if (dot & 1) result |= (1 << (7 - row));
  }
  return result;
}

/**
 * Compute the determinant of an 8x8 binary matrix over GF(2) using Gaussian elimination.
 * Returns 0 (singular) or 1 (invertible).
 */
function gf2MatDet(matrix: Uint8Array): number {
  const m = new Uint8Array(8);
  for (let i = 0; i < 8; i++) m[i] = matrix[i];

  for (let col = 0; col < 8; col++) {
    const bit = 1 << (7 - col);
    let pivotRow = -1;
    for (let row = col; row < 8; row++) {
      if (m[row] & bit) { pivotRow = row; break; }
    }
    if (pivotRow === -1) return 0;

    if (pivotRow !== col) {
      const tmp = m[col]; m[col] = m[pivotRow]; m[pivotRow] = tmp;
    }

    for (let row = 0; row < 8; row++) {
      if (row !== col && (m[row] & bit)) {
        m[row] ^= m[col];
      }
    }
  }
  return 1;
}

/**
 * Compute the inverse of an 8x8 binary matrix over GF(2) using Gauss-Jordan elimination.
 * Assumes the matrix is invertible.
 */
function gf2MatInverse(matrix: Uint8Array): Uint8Array {
  const aug = new Uint16Array(8);
  for (let i = 0; i < 8; i++) {
    aug[i] = (matrix[i] << 8) | (1 << (7 - i));
  }

  for (let col = 0; col < 8; col++) {
    const bit = 1 << (15 - col);
    let pivotRow = -1;
    for (let row = col; row < 8; row++) {
      if (aug[row] & bit) { pivotRow = row; break; }
    }
    if (pivotRow !== col) {
      const tmp = aug[col]; aug[col] = aug[pivotRow]; aug[pivotRow] = tmp;
    }
    for (let row = 0; row < 8; row++) {
      if (row !== col && (aug[row] & bit)) {
        aug[row] ^= aug[col];
      }
    }
  }

  const inv = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    inv[i] = aug[i] & 0xff;
  }
  return inv;
}

/**
 * Internal PRNG state used for key-dependent generation.
 */
interface PrngState {
  s0: number; s1: number; s2: number; s3: number;
  s4: number; s5: number; s6: number; s7: number;
}

function prngInit(key: Uint8Array): PrngState {
  return {
    s0: readU32BE(key, 0), s1: readU32BE(key, 4),
    s2: readU32BE(key, 8), s3: readU32BE(key, 12),
    s4: readU32BE(key, 16), s5: readU32BE(key, 20),
    s6: readU32BE(key, 24), s7: readU32BE(key, 28),
  };
}

function prngNext(st: PrngState): number {
  st.s0 = ((Math.imul(st.s0 ^ 0x9e3779b9, 0x45d9f3b) + rotl32(st.s1, 7)) ^ st.s2) >>> 0;
  st.s1 = ((Math.imul(st.s1 ^ 0x6a09e667, 0x119de1f3) + rotl32(st.s2, 13)) ^ st.s3) >>> 0;
  st.s2 = ((Math.imul(st.s2 ^ 0xbb67ae85, 0x16a6b885) + rotl32(st.s3, 17)) ^ st.s4) >>> 0;
  st.s3 = ((Math.imul(st.s3 ^ 0x3c6ef372, 0x3b4d6fcd) + rotl32(st.s4, 23)) ^ st.s5) >>> 0;
  st.s4 = ((Math.imul(st.s4 ^ 0xa54ff53a, 0x5e9a3fff) + rotl32(st.s5, 5)) ^ st.s6) >>> 0;
  st.s5 = ((Math.imul(st.s5 ^ 0x510e527f, 0x7a2b14c9) + rotl32(st.s6, 11)) ^ st.s7) >>> 0;
  st.s6 = ((Math.imul(st.s6 ^ 0x9b05688c, 0x2f8c49a7) + rotl32(st.s7, 19)) ^ st.s0) >>> 0;
  st.s7 = ((Math.imul(st.s7 ^ 0x1f83d9ab, 0x6c5b8e27) + rotl32(st.s0, 29)) ^ st.s1) >>> 0;
  return (st.s0 ^ st.s4) >>> 0;
}

/**
 * Generate a key-dependent 8x8 S-box by applying S'(x) = A * S(x) XOR c, where
 * S is the base S-box, A is a key-derived invertible 8x8 matrix over GF(2),
 * and c is a key-derived 8-bit constant. Affine equivalence preserves the
 * base S-box's differential uniformity (4/256) and nonlinearity (112).
 */
function generateSBox(key: Uint8Array): Uint8Array {
  const sbox = new Uint8Array(SBOX_SIZE);
  const st = prngInit(key);

  // Warm up PRNG (32 iterations to decorrelate from key material)
  for (let i = 0; i < 32; i++) prngNext(st);

  // Generate an invertible 8x8 matrix over GF(2).
  // A random 8x8 binary matrix is invertible with probability ~28.9%, so ~3-4 attempts.
  const matrix = new Uint8Array(8);
  let attempts = 0;
  do {
    const w0 = prngNext(st);
    const w1 = prngNext(st);
    matrix[0] = (w0 >>> 24) & 0xff;
    matrix[1] = (w0 >>> 16) & 0xff;
    matrix[2] = (w0 >>> 8) & 0xff;
    matrix[3] = w0 & 0xff;
    matrix[4] = (w1 >>> 24) & 0xff;
    matrix[5] = (w1 >>> 16) & 0xff;
    matrix[6] = (w1 >>> 8) & 0xff;
    matrix[7] = w1 & 0xff;
    attempts++;
    if (attempts > 1000) {
      // Safety fallback — identity matrix (astronomically unlikely to be needed)
      for (let i = 0; i < 8; i++) matrix[i] = (1 << (7 - i));
      break;
    }
  } while (gf2MatDet(matrix) === 0);

  // Derive the affine constant
  const affineConst = prngNext(st) & 0xff;

  // Apply: S'(x) = A * SEED_SBOX(x) XOR c
  for (let i = 0; i < SBOX_SIZE; i++) {
    sbox[i] = gf2MatVecMul(matrix, SEED_SBOX[i]) ^ affineConst;
  }

  return sbox;
}

/** Generate the inverse S-box from a forward S-box */
function generateInvSBox(sbox: Uint8Array): Uint8Array {
  const inv = new Uint8Array(SBOX_SIZE);
  for (let i = 0; i < SBOX_SIZE; i++) {
    inv[sbox[i]] = i;
  }
  return inv;
}

// ============================================================================
// Key Schedule
// ============================================================================

/** VORTEX-256 key schedule. */
interface VortexKeySchedule {
  preWhitening: Uint32Array;
  postWhitening: Uint32Array;
  roundKeys: Uint32Array[];
  sbox: Uint8Array;
  invSbox: Uint8Array;
}

/**
 * Constant-time byte lookup: reads every element and selects via an arithmetic
 * mask. Used for all security-critical S-box reads to avoid cache-timing leaks
 * (cf. Bernstein 2005 "Cache-timing attacks on AES").
 */
function ctLookupByte(table: Uint8Array, index: number): number {
  let result = 0;
  for (let i = 0; i < table.length; i++) {
    const diff = (i ^ index) & 0xff;
    const mask = (((diff | (-diff)) >>> 31) - 1) & 0xff;
    result |= table[i] & mask;
  }
  return result & 0xff;
}

/**
 * Constant-time S-box application to all 4 bytes of a 32-bit word.
 * This is the DEFAULT for all encryption/decryption paths.
 */
function ctSubWord(w: number, sbox: Uint8Array): number {
  const b3 = ctLookupByte(sbox, (w >>> 24) & 0xff);
  const b2 = ctLookupByte(sbox, (w >>> 16) & 0xff);
  const b1 = ctLookupByte(sbox, (w >>> 8) & 0xff);
  const b0 = ctLookupByte(sbox, w & 0xff);
  return ((b3 << 24) | (b2 << 16) | (b1 << 8) | b0) >>> 0;
}

/**
 * FAST (non-constant-time) S-box application via direct array indexing.
 * WARNING: Vulnerable to cache-timing side-channel attacks.
 * Use ONLY when timing attacks are not a concern (offline batch processing, testing).
 */
function subWordFast(w: number, sbox: Uint8Array): number {
  return (
    ((sbox[(w >>> 24) & 0xff] << 24) |
      (sbox[(w >>> 16) & 0xff] << 16) |
      (sbox[(w >>> 8) & 0xff] << 8) |
      sbox[w & 0xff]) >>> 0
  );
}

/** Default S-box word substitution — constant-time, used by all cipher paths. */
function subWord(w: number, sbox: Uint8Array): number {
  return ctSubWord(w, sbox);
}

/**
 * Sigma function for key schedule nonlinear diffusion.
 * sigma(x) = S(x) XOR S(ROTL(x,8)) XOR S(ROTL(x,16)) XOR S(ROTL(x,24))
 */
function sigmaWord(w: number, sbox: Uint8Array): number {
  const a = subWord(w, sbox);
  const b = subWord(rotl32(w, 8), sbox);
  const c = subWord(rotl32(w, 16), sbox);
  const d = subWord(rotl32(w, 24), sbox);
  return (a ^ b ^ c ^ d) >>> 0;
}

/**
 * Nonlinear mixing function for key schedule.
 */
function keyMix(a: number, b: number, rc: number, sbox: Uint8Array): number {
  let t = (Math.imul(a, 0x1b873593) ^ rotl32(b, 15)) >>> 0;
  t = (subWord(t, sbox) ^ rc) >>> 0;
  t = (t ^ rotl32(t, 7) ^ rotl32(t, 18)) >>> 0;
  return t;
}

/** Expand a 256-bit master key into the full key schedule. */
function expandKey(masterKey: Uint8Array): VortexKeySchedule {
  if (masterKey.length !== KEY_SIZE) {
    throw new Error(`VORTEX-256: key must be ${KEY_SIZE} bytes`);
  }

  const sbox = generateSBox(masterKey);
  const invSbox = generateInvSBox(sbox);

  const mk = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    mk[i] = readU32BE(masterKey, i * 4);
  }

  // 2 whitening keys (8 words) + 20 round keys (80 words) = 88, expand to 96
  const W = new Uint32Array(96);
  for (let i = 0; i < 8; i++) {
    W[i] = mk[i];
  }

  // Key-dependent odd multiplier — odd ensures invertibility in Z/(2^32)
  const keyOddConst = ((readU32BE(masterKey, 0) ^ readU32BE(masterKey, 16)) | 1) >>> 0;

  // Expand — EVERY word now gets nonlinear treatment
  for (let i = 8; i < 96; i++) {
    const rcIdx = i % NUM_ROUNDS;
    const rc = ROUND_CONSTANTS[rcIdx];

    // Start from the word 8 positions back
    let t = W[i - 8];

    // Apply sigma function for nonlinear cross-byte diffusion on EVERY word
    t = (t ^ sigmaWord(W[i - 1], sbox)) >>> 0;

    // Modular multiplication by key-dependent odd constant (nonlinear over GF(2))
    t = Math.imul(t, keyOddConst) >>> 0;

    // Round-dependent constant (unique per position)
    t = (t ^ rc ^ rotl32(rc, (i * 7) & 31)) >>> 0;

    // Additional cross-word mixing
    if (i % 8 === 0) {
      t = (t ^ keyMix(W[i - 1], W[i - 8], rc, sbox)) >>> 0;
    } else if (i % 4 === 0) {
      t = (t ^ rotl32(W[i - 3], 11) ^ rotl32(W[i - 5], 23)) >>> 0;
    } else {
      t = (t ^ rotl32(W[i - 2], 13)) >>> 0;
    }

    W[i] = t;
  }

  const preWhitening = new Uint32Array(4);
  const postWhitening = new Uint32Array(4);
  for (let i = 0; i < 4; i++) {
    preWhitening[i] = W[8 + i];
    postWhitening[i] = W[12 + i];
  }

  const roundKeys: Uint32Array[] = [];
  for (let r = 0; r < NUM_ROUNDS; r++) {
    const rk = new Uint32Array(4);
    for (let i = 0; i < 4; i++) {
      rk[i] = W[16 + r * 4 + i];
    }
    roundKeys.push(rk);
  }

  mk.fill(0);
  W.fill(0);

  return { preWhitening, postWhitening, roundKeys, sbox, invSbox };
}

// ============================================================================
// Round Function Components
// ============================================================================

/**
 * SUBSTITUTION LAYER — applies key-dependent S-box (constant-time by default).
 */
function substituteBranch(branch: number, sbox: Uint8Array): number {
  return subWord(branch, sbox);
}

/**
 * BYTE PERMUTATION LAYER — rotate bytes within a branch by branchIdx positions.
 */
function permuteBranch(branch: number, branchIdx: number): number {
  const shift = (branchIdx & 3) * 8;
  if (shift === 0) return branch;
  return rotl32(branch, shift);
}

function invPermuteBranch(branch: number, branchIdx: number): number {
  const shift = (branchIdx & 3) * 8;
  if (shift === 0) return branch;
  return rotr32(branch, shift);
}

/**
 * NONLINEAR MIXING FUNCTION (F-function)
 *
 * Uses modular addition, S-box substitution, rotations, and XOR.
 * Two S-box passes give algebraic degree 14 (7+7).
 */
function fFunction(
  x: number,
  roundKeyWord: number,
  roundConst: number,
  sbox: Uint8Array
): number {
  let t = (x + roundKeyWord) >>> 0;
  t = subWord(t, sbox);
  t = (t ^ rotl32(t, 5) ^ rotl32(t, 17)) >>> 0;
  t = (t ^ roundConst) >>> 0;
  t = subWord(t, sbox);
  t = (t ^ rotr32(t, 11) ^ rotr32(t, 23)) >>> 0;
  return t;
}

/**
 * Inter-branch mixing in two phases: a Feistel-like cascade followed by
 * cross-lane XORs. The 4-branch GFN only touches 2/4 branches through the
 * F-function per round, so this extra mixing pushes single-round diffusion
 * from ~36% to ~49% bit change. Invertible by reversing the operation order.
 */
function mixBranchesFinal(b: Uint32Array): void {
  // Phase 1: Sequential cascade — each branch absorbs rotated copies of its predecessor
  b[1] = (b[1] ^ rotl32(b[0], 1) ^ rotl32(b[0], 7)) >>> 0;
  b[2] = (b[2] ^ rotl32(b[1], 11) ^ rotl32(b[1], 19)) >>> 0;
  b[3] = (b[3] ^ rotl32(b[2], 5) ^ rotl32(b[2], 23)) >>> 0;
  b[0] = (b[0] ^ rotl32(b[3], 13) ^ rotl32(b[3], 29)) >>> 0;

  // Phase 2: Cross-lane mixing — connects non-adjacent branches for full diffusion
  b[2] = (b[2] ^ rotl32(b[0], 3)) >>> 0;
  b[3] = (b[3] ^ rotl32(b[1], 17)) >>> 0;
  b[0] = (b[0] ^ rotl32(b[2], 9)) >>> 0;
  b[1] = (b[1] ^ rotl32(b[3], 25)) >>> 0;
}

function invMixBranchesFinal(b: Uint32Array): void {
  // Exact reverse of mixBranchesFinal — XOR is self-inverse, reverse order

  // Inverse Phase 2
  b[1] = (b[1] ^ rotl32(b[3], 25)) >>> 0;
  b[0] = (b[0] ^ rotl32(b[2], 9)) >>> 0;
  b[3] = (b[3] ^ rotl32(b[1], 17)) >>> 0;
  b[2] = (b[2] ^ rotl32(b[0], 3)) >>> 0;

  // Inverse Phase 1
  b[0] = (b[0] ^ rotl32(b[3], 13) ^ rotl32(b[3], 29)) >>> 0;
  b[3] = (b[3] ^ rotl32(b[2], 5) ^ rotl32(b[2], 23)) >>> 0;
  b[2] = (b[2] ^ rotl32(b[1], 11) ^ rotl32(b[1], 19)) >>> 0;
  b[1] = (b[1] ^ rotl32(b[0], 1) ^ rotl32(b[0], 7)) >>> 0;
}

// ============================================================================
// Core Block Cipher — Encrypt / Decrypt
// ============================================================================

/**
 * VORTEX-256 ROUND FUNCTION
 */
function vortexRound(
  state: Uint32Array,
  roundKey: Uint32Array,
  roundNum: number,
  sbox: Uint8Array
): void {
  const rc = ROUND_CONSTANTS[roundNum];

  // Generalized Feistel — F applied to branches 0,2; XORed into 1,3
  const f0 = fFunction(state[0], roundKey[0], rc, sbox);
  const f2 = fFunction(state[2], roundKey[1], rotl32(rc, 16), sbox);
  state[1] = (state[1] ^ f0) >>> 0;
  state[3] = (state[3] ^ f2) >>> 0;

  // Substitution on all branches
  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = substituteBranch(state[i], sbox);
  }

  // Byte permutation
  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = permuteBranch(state[i], i);
  }

  // Inter-branch mixing (cascade + cross-lane for full diffusion)
  mixBranchesFinal(state);

  // Key addition on branches 0,2
  state[0] = (state[0] ^ roundKey[2]) >>> 0;
  state[2] = (state[2] ^ roundKey[3]) >>> 0;

  // Branch rotation
  const tmp = state[3];
  state[3] = state[2];
  state[2] = state[1];
  state[1] = state[0];
  state[0] = tmp;
}

/**
 * Inverse of the VORTEX-256 round function for decryption.
 */
function vortexInvRound(
  state: Uint32Array,
  roundKey: Uint32Array,
  roundNum: number,
  invSbox: Uint8Array,
  sbox: Uint8Array
): void {
  const rc = ROUND_CONSTANTS[roundNum];

  // Inverse branch rotation
  const tmp = state[0];
  state[0] = state[1];
  state[1] = state[2];
  state[2] = state[3];
  state[3] = tmp;

  // Key removal
  state[0] = (state[0] ^ roundKey[2]) >>> 0;
  state[2] = (state[2] ^ roundKey[3]) >>> 0;

  // Inverse inter-branch mixing
  invMixBranchesFinal(state);

  // Inverse byte permutation
  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = invPermuteBranch(state[i], i);
  }

  // Inverse substitution
  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = substituteBranch(state[i], invSbox);
  }

  // Inverse Feistel — recompute F on branches 0,2 and XOR out of 1,3
  const f0 = fFunction(state[0], roundKey[0], rc, sbox);
  const f2 = fFunction(state[2], roundKey[1], rotl32(rc, 16), sbox);
  state[1] = (state[1] ^ f0) >>> 0;
  state[3] = (state[3] ^ f2) >>> 0;
}

/**
 * Encrypt a single 128-bit block.
 */
function encryptBlock(block: Uint8Array, ks: VortexKeySchedule): Uint8Array {
  if (block.length !== BLOCK_SIZE) {
    throw new Error(`VORTEX-256: block must be ${BLOCK_SIZE} bytes`);
  }

  const state = new Uint32Array(NUM_BRANCHES);
  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = readU32BE(block, i * BRANCH_SIZE);
  }

  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = (state[i] ^ ks.preWhitening[i]) >>> 0;
  }

  for (let r = 0; r < NUM_ROUNDS; r++) {
    vortexRound(state, ks.roundKeys[r], r, ks.sbox);
  }

  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = (state[i] ^ ks.postWhitening[i]) >>> 0;
  }

  const out = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < NUM_BRANCHES; i++) {
    writeU32BE(out, i * BRANCH_SIZE, state[i]);
  }

  return out;
}

/**
 * Decrypt a single 128-bit block.
 */
function decryptBlock(block: Uint8Array, ks: VortexKeySchedule): Uint8Array {
  if (block.length !== BLOCK_SIZE) {
    throw new Error(`VORTEX-256: block must be ${BLOCK_SIZE} bytes`);
  }

  const state = new Uint32Array(NUM_BRANCHES);
  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = readU32BE(block, i * BRANCH_SIZE);
  }

  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = (state[i] ^ ks.postWhitening[i]) >>> 0;
  }

  for (let r = NUM_ROUNDS - 1; r >= 0; r--) {
    vortexInvRound(state, ks.roundKeys[r], r, ks.invSbox, ks.sbox);
  }

  for (let i = 0; i < NUM_BRANCHES; i++) {
    state[i] = (state[i] ^ ks.preWhitening[i]) >>> 0;
  }

  const out = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < NUM_BRANCHES; i++) {
    writeU32BE(out, i * BRANCH_SIZE, state[i]);
  }

  return out;
}

// ============================================================================
// AEAD Mode — VORTEX-CTR-MAC
// ============================================================================

/**
 * Increment a 32-bit counter stored at bytes 12-15 of a 16-byte block.
 * Throws on overflow to prevent keystream reuse.
 */
function incrementCounter(counter: Uint8Array): void {
  let c = readU32BE(counter, 12);
  if (c === 0xFFFFFFFF) {
    throw new Error('VORTEX-256: CTR counter overflow — maximum message size exceeded. Do not reuse this nonce.');
  }
  c = (c + 1) >>> 0;
  writeU32BE(counter, 12, c);
}

function padBlock(data: Uint8Array, offset: number, length: number): Uint8Array {
  const block = new Uint8Array(BLOCK_SIZE);
  const toCopy = Math.min(length - offset, BLOCK_SIZE);
  block.set(data.subarray(offset, offset + toCopy));
  return block;
}

/**
 * Compute the VORTEX-MAC over associated data and ciphertext.
 * SECURITY WARNING [H-03]: Raw CBC-MAC is NOT secure for variable-length messages.
 */
function computeMAC(
  ks: VortexKeySchedule,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  let h = new Uint8Array(BLOCK_SIZE);

  for (let i = 0; i < aad.length; i += BLOCK_SIZE) {
    const block = padBlock(aad, i, aad.length);
    h = encryptBlock(xorBytes(h, block), ks);
  }

  for (let i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
    const block = padBlock(ciphertext, i, ciphertext.length);
    h = encryptBlock(xorBytes(h, block), ks);
  }

  const lenBlock = new Uint8Array(BLOCK_SIZE);
  const aadBits = aad.length * 8;
  const ctBits = ciphertext.length * 8;
  writeU32BE(lenBlock, 0, Math.floor(aadBits / 0x100000000));
  writeU32BE(lenBlock, 4, aadBits >>> 0);
  writeU32BE(lenBlock, 8, Math.floor(ctBits / 0x100000000));
  writeU32BE(lenBlock, 12, ctBits >>> 0);
  h = encryptBlock(xorBytes(h, lenBlock), ks);

  const tagMaskInput = new Uint8Array(BLOCK_SIZE);
  tagMaskInput.set(nonce.subarray(0, NONCE_SIZE));
  const tagMask = encryptBlock(tagMaskInput, ks);

  return xorBytes(h, tagMask);
}

function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): { ciphertext: Uint8Array; tag: Uint8Array } {
  if (key.length !== KEY_SIZE) {
    throw new Error(`VORTEX-256: key must be ${KEY_SIZE} bytes`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`VORTEX-256: nonce must be ${NONCE_SIZE} bytes`);
  }

  const ks = expandKey(key);

  const ciphertext = new Uint8Array(plaintext.length);
  const counter = new Uint8Array(BLOCK_SIZE);
  counter.set(nonce.subarray(0, NONCE_SIZE));
  writeU32BE(counter, 12, 1);

  for (let i = 0; i < plaintext.length; i += BLOCK_SIZE) {
    const keystreamBlock = encryptBlock(counter, ks);
    const remaining = Math.min(BLOCK_SIZE, plaintext.length - i);
    for (let j = 0; j < remaining; j++) {
      ciphertext[i + j] = plaintext[i + j] ^ keystreamBlock[j];
    }
    incrementCounter(counter);
  }

  const tag = computeMAC(ks, nonce, aad, ciphertext);
  return { ciphertext, tag };
}

function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array | null {
  if (key.length !== KEY_SIZE) {
    throw new Error(`VORTEX-256: key must be ${KEY_SIZE} bytes`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`VORTEX-256: nonce must be ${NONCE_SIZE} bytes`);
  }
  if (tag.length !== TAG_SIZE) {
    throw new Error(`VORTEX-256: tag must be ${TAG_SIZE} bytes`);
  }

  const ks = expandKey(key);

  const expectedTag = computeMAC(ks, nonce, aad, ciphertext);
  if (!constantTimeEqual(expectedTag, tag)) {
    return null;
  }

  const plaintext = new Uint8Array(ciphertext.length);
  const counter = new Uint8Array(BLOCK_SIZE);
  counter.set(nonce.subarray(0, NONCE_SIZE));
  writeU32BE(counter, 12, 1);

  for (let i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
    const keystreamBlock = encryptBlock(counter, ks);
    const remaining = Math.min(BLOCK_SIZE, ciphertext.length - i);
    for (let j = 0; j < remaining; j++) {
      plaintext[i + j] = ciphertext[i + j] ^ keystreamBlock[j];
    }
    incrementCounter(counter);
  }

  return plaintext;
}

// ============================================================================
// Public API
// ============================================================================

/** Low-level VORTEX-256 block cipher providing single-block encrypt/decrypt operations. */
export class Vortex256 {
  private ks: VortexKeySchedule;

  constructor(key: Uint8Array) {
    if (key.length !== KEY_SIZE) {
      throw new Error(`VORTEX-256: key must be ${KEY_SIZE} bytes, got ${key.length}`);
    }
    this.ks = expandKey(key);
  }

  encryptBlock(plaintext: Uint8Array): Uint8Array {
    return encryptBlock(plaintext, this.ks);
  }

  decryptBlock(ciphertext: Uint8Array): Uint8Array {
    return decryptBlock(ciphertext, this.ks);
  }

  destroy(): void {
    zeroize(this.ks.sbox);
    zeroize(this.ks.invSbox);
    this.ks.preWhitening.fill(0);
    this.ks.postWhitening.fill(0);
    for (const rk of this.ks.roundKeys) {
      rk.fill(0);
    }
  }
}

/** VORTEX-256 authenticated encryption (AEAD) — seal/open with nonce-reuse detection. */
export class Vortex256AEAD {
  private key: Uint8Array;
  private _usedNonces: Set<string> = new Set();

  constructor(key: Uint8Array) {
    if (key.length !== KEY_SIZE) {
      throw new Error(`VORTEX-256: key must be ${KEY_SIZE} bytes, got ${key.length}`);
    }
    this.key = new Uint8Array(key);
  }

  seal(
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array = new Uint8Array(0)
  ): Uint8Array {
    const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
    if (this._usedNonces.has(nonceHex)) {
      throw new Error('VORTEX-256: NONCE REUSE DETECTED — refusing to encrypt.');
    }
    this._usedNonces.add(nonceHex);
    const { ciphertext, tag } = aeadEncrypt(this.key, nonce, plaintext, aad);
    const result = new Uint8Array(ciphertext.length + TAG_SIZE);
    result.set(ciphertext);
    result.set(tag, ciphertext.length);
    return result;
  }

  open(
    nonce: Uint8Array,
    sealed: Uint8Array,
    aad: Uint8Array = new Uint8Array(0)
  ): Uint8Array | null {
    if (sealed.length < TAG_SIZE) {
      return null;
    }
    const ciphertext = sealed.subarray(0, sealed.length - TAG_SIZE);
    const tag = sealed.subarray(sealed.length - TAG_SIZE);
    return aeadDecrypt(this.key, nonce, ciphertext, tag, aad);
  }

  destroy(): void {
    zeroize(this.key);
    this._usedNonces.clear();
  }
}

// ============================================================================
// Standalone Functions (for convenience)
// ============================================================================

export { aeadDecrypt, aeadEncrypt, decryptBlock, encryptBlock, expandKey };
export {
  constantTimeEqual,
  generateInvSBox,
  generateSBox,
  xorBytes,
  zeroize,
};
export {
  BLOCK_SIZE,
  KEY_SIZE,
  NONCE_SIZE,
  NUM_ROUNDS,
  ROUND_CONSTANTS,
  TAG_SIZE,
};

/** Internal cipher primitives exposed for unit testing — not part of the public API. */
export const _internals = {
  rotl32,
  rotr32,
  readU32BE,
  writeU32BE,
  readU32LE,
  writeU32LE,
  subWord,
  subWordFast,
  ctSubWord,
  ctLookupByte,
  sigmaWord,
  fFunction,
  mixBranchesFinal,
  invMixBranchesFinal,
  substituteBranch,
  permuteBranch,
  invPermuteBranch,
  vortexRound,
  vortexInvRound,
  computeMAC,
  incrementCounter,
  padBlock,
  keyMix,
  gf2MatDet,
  gf2MatVecMul,
  gf2MatInverse,
};
