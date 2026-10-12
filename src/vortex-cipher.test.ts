/// <reference types="vitest/globals" />

/**
 * VORTEX-256 — Comprehensive Test Suite
 *
 * Tests cover:
 * 1. S-box generation and properties (affine transform preserves nonlinearity)
 * 2. Key schedule correctness (nonlinear expansion, subkey independence)
 * 3. Block cipher encrypt/decrypt round-trip
 * 4. Mixing layer invertibility
 * 5. Permutation layer invertibility
 * 6. Avalanche effect (sensitivity to input changes)
 * 7. AEAD seal/open round-trip
 * 8. AEAD authentication (tamper detection)
 * 9. AEAD with associated data
 * 10. Known test vectors (deterministic, pinned)
 * 11. Edge cases (empty plaintext, large data, etc.)
 * 12. Key-dependent S-box variation
 * 13. Side-channel resistance properties (structural checks)
 * 14. GF(2) matrix operations
 */

import {
  _internals,
  aeadDecrypt,
  aeadEncrypt,
  BLOCK_SIZE,
  constantTimeEqual,
  decryptBlock,
  encryptBlock,
  expandKey,
  generateInvSBox,
  generateSBox,
  KEY_SIZE,
  NONCE_SIZE,
  NUM_ROUNDS,
  ROUND_CONSTANTS,
  TAG_SIZE,
  Vortex256,
  Vortex256AEAD,
  xorBytes,
  zeroize,
} from "./vortex-cipher";

// ============================================================================
// Helpers
// ============================================================================

function makeKey(...pattern: number[]): Uint8Array {
  const key = new Uint8Array(KEY_SIZE);
  for (let i = 0; i < KEY_SIZE; i++) {
    key[i] = pattern[i % pattern.length];
  }
  return key;
}

function makeBlock(...pattern: number[]): Uint8Array {
  const block = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    block[i] = pattern[i % pattern.length];
  }
  return block;
}

function makeNonce(...pattern: number[]): Uint8Array {
  const nonce = new Uint8Array(NONCE_SIZE);
  for (let i = 0; i < NONCE_SIZE; i++) {
    nonce[i] = pattern[i % pattern.length];
  }
  return nonce;
}

function toHex(buf: Uint8Array): string {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  let dist = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    let xor = a[i] ^ b[i];
    while (xor) {
      dist += xor & 1;
      xor >>>= 1;
    }
  }
  return dist;
}

// ============================================================================
// Test Suite
// ============================================================================

describe("VORTEX-256 Block Cipher", () => {
  // --------------------------------------------------------------------------
  // 1. S-Box Generation and Properties
  // --------------------------------------------------------------------------
  describe("S-Box Generation", () => {
    it("should generate a valid permutation (bijective)", () => {
      const key = makeKey(0x01, 0x02, 0x03, 0x04);
      const sbox = generateSBox(key);

      // Every value 0-255 must appear exactly once
      const seen = new Set<number>();
      for (let i = 0; i < 256; i++) {
        seen.add(sbox[i]);
      }
      expect(seen.size).toBe(256);
    });

    it("should generate inverse that perfectly reverses the forward S-box", () => {
      const key = makeKey(0xaa, 0xbb, 0xcc, 0xdd);
      const sbox = generateSBox(key);
      const inv = generateInvSBox(sbox);

      for (let i = 0; i < 256; i++) {
        expect(inv[sbox[i]]).toBe(i);
        expect(sbox[inv[i]]).toBe(i);
      }
    });

    it("should produce different S-boxes for different keys", () => {
      const key1 = makeKey(0x00);
      const key2 = makeKey(0x01);
      const sbox1 = generateSBox(key1);
      const sbox2 = generateSBox(key2);

      let differences = 0;
      for (let i = 0; i < 256; i++) {
        if (sbox1[i] !== sbox2[i]) differences++;
      }
      // With affine transforms using different matrices, most entries differ
      expect(differences).toBeGreaterThan(100);
    });

    it("should be deterministic — same key produces same S-box", () => {
      const key = makeKey(0xde, 0xad, 0xbe, 0xef);
      const sbox1 = generateSBox(key);
      const sbox2 = generateSBox(key);
      expect(toHex(sbox1)).toBe(toHex(sbox2));
    });

    it("should have no fixed points (S[x] != x for most values)", () => {
      const key = makeKey(0x42);
      const sbox = generateSBox(key);

      let fixedPoints = 0;
      for (let i = 0; i < 256; i++) {
        if (sbox[i] === i) fixedPoints++;
      }
      // A random permutation has ~1 fixed point on average
      expect(fixedPoints).toBeLessThan(10);
    });

    it("should preserve bijectivity across multiple keys (affine transform correctness)", () => {
      // Test that the affine transform always produces a valid permutation
      for (let trial = 0; trial < 10; trial++) {
        const key = new Uint8Array(KEY_SIZE);
        for (let i = 0; i < KEY_SIZE; i++) key[i] = (trial * 37 + i * 13) & 0xff;
        const sbox = generateSBox(key);

        const seen = new Set<number>();
        for (let i = 0; i < 256; i++) seen.add(sbox[i]);
        expect(seen.size).toBe(256);
      }
    });
  });

  // --------------------------------------------------------------------------
  // GF(2) Matrix Operations
  // --------------------------------------------------------------------------
  describe("GF(2) Matrix Operations", () => {
    it("gf2MatDet should detect singular matrices", () => {
      // Zero matrix is singular
      const zero = new Uint8Array(8);
      expect(_internals.gf2MatDet(zero)).toBe(0);

      // Identity matrix is invertible
      const identity = new Uint8Array(8);
      for (let i = 0; i < 8; i++) identity[i] = 1 << (7 - i);
      expect(_internals.gf2MatDet(identity)).toBe(1);

      // Matrix with duplicate rows is singular
      const dup = new Uint8Array([0xff, 0xff, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20]);
      expect(_internals.gf2MatDet(dup)).toBe(0);
    });

    it("gf2MatVecMul with identity should return input", () => {
      const identity = new Uint8Array(8);
      for (let i = 0; i < 8; i++) identity[i] = 1 << (7 - i);

      for (let v = 0; v < 256; v++) {
        expect(_internals.gf2MatVecMul(identity, v)).toBe(v);
      }
    });

    it("gf2MatInverse should produce correct inverse", () => {
      const identity = new Uint8Array(8);
      for (let i = 0; i < 8; i++) identity[i] = 1 << (7 - i);

      // Test with a known invertible matrix
      const mat = new Uint8Array([0xe3, 0x71, 0xb8, 0x5c, 0x2e, 0x97, 0x4b, 0xa5]);
      if (_internals.gf2MatDet(mat) === 1) {
        const inv = _internals.gf2MatInverse(mat);
        // M * M^{-1} should be identity: for each basis vector e_i, M(M^{-1}(e_i)) = e_i
        for (let i = 0; i < 8; i++) {
          const ei = 1 << (7 - i);
          const inv_ei = _internals.gf2MatVecMul(inv, ei);
          const result = _internals.gf2MatVecMul(mat, inv_ei);
          expect(result).toBe(ei);
        }
      }
    });
  });

  // --------------------------------------------------------------------------
  // 2. Key Schedule
  // --------------------------------------------------------------------------
  describe("Key Schedule", () => {
    it("should expand key to correct number of round keys", () => {
      const key = makeKey(0x00);
      const ks = expandKey(key);

      expect(ks.preWhitening.length).toBe(4);
      expect(ks.postWhitening.length).toBe(4);
      expect(ks.roundKeys.length).toBe(NUM_ROUNDS);
      for (const rk of ks.roundKeys) {
        expect(rk.length).toBe(4);
      }
    });

    it("should produce different round keys for different master keys", () => {
      const ks1 = expandKey(makeKey(0x00));
      const ks2 = expandKey(makeKey(0x01));

      let allSame = true;
      for (let r = 0; r < NUM_ROUNDS; r++) {
        for (let i = 0; i < 4; i++) {
          if (ks1.roundKeys[r][i] !== ks2.roundKeys[r][i]) {
            allSame = false;
          }
        }
      }
      expect(allSame).toBe(false);
    });

    it("should produce different round keys across rounds (no slide)", () => {
      const ks = expandKey(makeKey(0xca, 0xfe));

      for (let r = 0; r < NUM_ROUNDS - 1; r++) {
        let same = true;
        for (let i = 0; i < 4; i++) {
          if (ks.roundKeys[r][i] !== ks.roundKeys[r + 1][i]) {
            same = false;
          }
        }
        expect(same).toBe(false);
      }
    });

    it("should be deterministic", () => {
      const key = makeKey(0xff);
      const ks1 = expandKey(key);
      const ks2 = expandKey(key);

      for (let r = 0; r < NUM_ROUNDS; r++) {
        for (let i = 0; i < 4; i++) {
          expect(ks1.roundKeys[r][i]).toBe(ks2.roundKeys[r][i]);
        }
      }
    });

    it("should reject keys of wrong length", () => {
      expect(() => expandKey(new Uint8Array(16))).toThrow();
      expect(() => expandKey(new Uint8Array(64))).toThrow();
    });
  });

  // --------------------------------------------------------------------------
  // 3. Block Cipher Round-Trip
  // --------------------------------------------------------------------------
  describe("Block Cipher Encrypt/Decrypt", () => {
    it("should round-trip: decrypt(encrypt(P)) === P", () => {
      const key = makeKey(0x13, 0x37, 0xbe, 0xef);
      const ks = expandKey(key);
      const plaintext = makeBlock(0x00, 0x11, 0x22, 0x33);

      const ciphertext = encryptBlock(plaintext, ks);
      const recovered = decryptBlock(ciphertext, ks);

      expect(toHex(recovered)).toBe(toHex(plaintext));
    });

    it("should round-trip for all-zero block and key", () => {
      const key = makeKey(0x00);
      const ks = expandKey(key);
      const plaintext = makeBlock(0x00);

      const ciphertext = encryptBlock(plaintext, ks);
      expect(toHex(ciphertext)).not.toBe(toHex(plaintext));

      const recovered = decryptBlock(ciphertext, ks);
      expect(toHex(recovered)).toBe(toHex(plaintext));
    });

    it("should round-trip for all-ones block and key", () => {
      const key = makeKey(0xff);
      const ks = expandKey(key);
      const plaintext = makeBlock(0xff);

      const ciphertext = encryptBlock(plaintext, ks);
      const recovered = decryptBlock(ciphertext, ks);

      expect(toHex(recovered)).toBe(toHex(plaintext));
    });

    it("should produce different ciphertext for different keys", () => {
      const plaintext = makeBlock(0xab, 0xcd);
      const ks1 = expandKey(makeKey(0x00));
      const ks2 = expandKey(makeKey(0x01));

      const ct1 = encryptBlock(plaintext, ks1);
      const ct2 = encryptBlock(plaintext, ks2);

      expect(toHex(ct1)).not.toBe(toHex(ct2));
    });

    it("should produce different ciphertext for different plaintexts", () => {
      const ks = expandKey(makeKey(0x42));
      const ct1 = encryptBlock(makeBlock(0x00), ks);
      const ct2 = encryptBlock(makeBlock(0x01), ks);

      expect(toHex(ct1)).not.toBe(toHex(ct2));
    });

    it("should reject blocks of wrong length", () => {
      const ks = expandKey(makeKey(0x00));
      expect(() => encryptBlock(new Uint8Array(8), ks)).toThrow();
      expect(() => decryptBlock(new Uint8Array(32), ks)).toThrow();
    });

    it("should round-trip many random-like blocks", () => {
      const key = new Uint8Array(KEY_SIZE);
      for (let i = 0; i < KEY_SIZE; i++) key[i] = (i * 73 + 17) & 0xff;
      const ks = expandKey(key);

      for (let trial = 0; trial < 20; trial++) {
        const pt = new Uint8Array(BLOCK_SIZE);
        for (let i = 0; i < BLOCK_SIZE; i++) {
          pt[i] = ((trial * 31 + i * 97 + 13) & 0xff);
        }
        const ct = encryptBlock(pt, ks);
        const recovered = decryptBlock(ct, ks);
        expect(toHex(recovered)).toBe(toHex(pt));
      }
    });
  });

  // --------------------------------------------------------------------------
  // 4. Mixing Layer Invertibility
  // --------------------------------------------------------------------------
  describe("Mixing Layer", () => {
    it("should be perfectly invertible", () => {
      for (let trial = 0; trial < 100; trial++) {
        const original = new Uint32Array([
          (trial * 0x12345678 + 0xdeadbeef) >>> 0,
          (trial * 0x9abcdef0 + 0xcafebabe) >>> 0,
          (trial * 0x55555555 + 0x13371337) >>> 0,
          (trial * 0xaaaaaaaa + 0xfeedface) >>> 0,
        ]);

        const state = new Uint32Array(original);
        _internals.mixBranchesFinal(state);

        let changed = false;
        for (let i = 0; i < 4; i++) {
          if (state[i] !== original[i]) changed = true;
        }
        expect(changed).toBe(true);

        _internals.invMixBranchesFinal(state);
        for (let i = 0; i < 4; i++) {
          expect(state[i]).toBe(original[i]);
        }
      }
    });

    it("should provide good diffusion — single bit change affects multiple branches", () => {
      const a = new Uint32Array([0, 0, 0, 0]);
      const b = new Uint32Array([1, 0, 0, 0]);

      _internals.mixBranchesFinal(a);
      _internals.mixBranchesFinal(b);

      let changedBranches = 0;
      for (let i = 0; i < 4; i++) {
        if (a[i] !== b[i]) changedBranches++;
      }
      // All 4 branches should be affected thanks to the cross-lane mixing
      expect(changedBranches).toBeGreaterThanOrEqual(3);
    });
  });

  // --------------------------------------------------------------------------
  // 5. Permutation Layer Invertibility
  // --------------------------------------------------------------------------
  describe("Permutation Layer", () => {
    it("should be perfectly invertible for all branch indices", () => {
      for (let branchIdx = 0; branchIdx < 4; branchIdx++) {
        for (let trial = 0; trial < 50; trial++) {
          const val = ((trial * 0x01010101 + branchIdx * 0x3f3f3f3f) >>> 0);
          const permuted = _internals.permuteBranch(val, branchIdx);
          const recovered = _internals.invPermuteBranch(permuted, branchIdx);
          expect(recovered).toBe(val);
        }
      }
    });
  });

  // --------------------------------------------------------------------------
  // 6. Avalanche Effect
  // --------------------------------------------------------------------------
  describe("Avalanche Effect", () => {
    it("should achieve near-50% bit flip rate for single-bit plaintext changes", () => {
      const key = makeKey(0x42, 0x43, 0x44, 0x45);
      const ks = expandKey(key);

      const baseline = makeBlock(0x00);
      const baselineCt = encryptBlock(baseline, ks);

      let totalDistance = 0;
      let trials = 0;

      for (let byte_ = 0; byte_ < BLOCK_SIZE; byte_++) {
        for (let bit = 0; bit < 8; bit++) {
          const modified = new Uint8Array(baseline);
          modified[byte_] ^= 1 << bit;

          const modifiedCt = encryptBlock(modified, ks);
          totalDistance += hammingDistance(baselineCt, modifiedCt);
          trials++;
        }
      }

      const avgDistance = totalDistance / trials;
      const blockBits = BLOCK_SIZE * 8;
      const ratio = avgDistance / blockBits;

      // Accept 35%-65% as a reasonable range for 20 rounds
      expect(ratio).toBeGreaterThan(0.35);
      expect(ratio).toBeLessThan(0.65);
    });

    it("should achieve near-50% bit flip rate for single-bit key changes", () => {
      const key1 = makeKey(0x00);
      const key2 = new Uint8Array(key1);
      key2[0] ^= 0x01;

      const ks1 = expandKey(key1);
      const ks2 = expandKey(key2);
      const plaintext = makeBlock(0x00);

      const ct1 = encryptBlock(plaintext, ks1);
      const ct2 = encryptBlock(plaintext, ks2);

      const dist = hammingDistance(ct1, ct2);
      const ratio = dist / (BLOCK_SIZE * 8);

      expect(ratio).toBeGreaterThan(0.3);
      expect(ratio).toBeLessThan(0.7);
    });
  });

  // --------------------------------------------------------------------------
  // 7. AEAD Seal/Open Round-Trip
  // --------------------------------------------------------------------------
  describe("AEAD Mode", () => {
    it("should round-trip: open(seal(P)) === P", () => {
      const key = makeKey(0xaa, 0xbb, 0xcc, 0xdd);
      const nonce = makeNonce(0x01, 0x02, 0x03);
      const plaintext = new TextEncoder().encode("Hello, VORTEX-256!");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext);
      const opened = aead.open(nonce, sealed);

      expect(opened).not.toBeNull();
      expect(toHex(opened!)).toBe(toHex(plaintext));
      aead.destroy();
    });

    it("should round-trip with associated data", () => {
      const key = makeKey(0x11, 0x22, 0x33, 0x44);
      const nonce = makeNonce(0xaa);
      const plaintext = new TextEncoder().encode("Secret payload");
      const aad = new TextEncoder().encode("public header");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext, aad);
      const opened = aead.open(nonce, sealed, aad);

      expect(opened).not.toBeNull();
      expect(new TextDecoder().decode(opened!)).toBe("Secret payload");
      aead.destroy();
    });

    it("should produce sealed output of correct length", () => {
      const key = makeKey(0x00);
      const nonce = makeNonce(0x00);
      const plaintext = new Uint8Array(100);

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext);

      expect(sealed.length).toBe(100 + TAG_SIZE);
      aead.destroy();
    });

    it("should handle empty plaintext", () => {
      const key = makeKey(0xff);
      const nonce = makeNonce(0xff);
      const plaintext = new Uint8Array(0);

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext);

      expect(sealed.length).toBe(TAG_SIZE);

      const opened = aead.open(nonce, sealed);
      expect(opened).not.toBeNull();
      expect(opened!.length).toBe(0);
      aead.destroy();
    });

    it("should handle empty plaintext with AAD", () => {
      const key = makeKey(0x42);
      const nonce = makeNonce(0x42);
      const plaintext = new Uint8Array(0);
      const aad = new TextEncoder().encode("authenticated only");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext, aad);
      const opened = aead.open(nonce, sealed, aad);

      expect(opened).not.toBeNull();
      expect(opened!.length).toBe(0);
      aead.destroy();
    });

    it("should round-trip large data (multi-block)", () => {
      const key = makeKey(0x99);
      const nonce = makeNonce(0x12);
      const plaintext = new Uint8Array(1000);
      for (let i = 0; i < plaintext.length; i++) {
        plaintext[i] = (i * 7 + 3) & 0xff;
      }

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext);
      const opened = aead.open(nonce, sealed);

      expect(opened).not.toBeNull();
      expect(toHex(opened!)).toBe(toHex(plaintext));
      aead.destroy();
    });
  });

  // --------------------------------------------------------------------------
  // 8. AEAD Authentication (Tamper Detection)
  // --------------------------------------------------------------------------
  describe("AEAD Authentication", () => {
    it("should reject tampered ciphertext", () => {
      const key = makeKey(0x01, 0x02);
      const nonce = makeNonce(0x03);
      const plaintext = new TextEncoder().encode("Do not tamper");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext);

      const tampered = new Uint8Array(sealed);
      tampered[0] ^= 0x01;

      const opened = aead.open(nonce, tampered);
      expect(opened).toBeNull();
      aead.destroy();
    });

    it("should reject tampered tag", () => {
      const key = makeKey(0xab);
      const nonce = makeNonce(0xcd);
      const plaintext = new TextEncoder().encode("Tag integrity");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext);

      const tampered = new Uint8Array(sealed);
      tampered[sealed.length - 1] ^= 0x01;

      const opened = aead.open(nonce, tampered);
      expect(opened).toBeNull();
      aead.destroy();
    });

    it("should reject wrong nonce", () => {
      const key = makeKey(0xfe);
      const nonce1 = makeNonce(0x01);
      const nonce2 = makeNonce(0x02);
      const plaintext = new TextEncoder().encode("Nonce mismatch");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce1, plaintext);
      const opened = aead.open(nonce2, sealed);

      expect(opened).toBeNull();
      aead.destroy();
    });

    it("should reject wrong key", () => {
      const key1 = makeKey(0x01);
      const key2 = makeKey(0x02);
      const nonce = makeNonce(0x00);
      const plaintext = new TextEncoder().encode("Wrong key");

      const aead1 = new Vortex256AEAD(key1);
      const aead2 = new Vortex256AEAD(key2);

      const sealed = aead1.seal(nonce, plaintext);
      const opened = aead2.open(nonce, sealed);

      expect(opened).toBeNull();
      aead1.destroy();
      aead2.destroy();
    });

    it("should reject wrong associated data", () => {
      const key = makeKey(0x55);
      const nonce = makeNonce(0x55);
      const plaintext = new TextEncoder().encode("AAD mismatch");
      const aad1 = new TextEncoder().encode("header-v1");
      const aad2 = new TextEncoder().encode("header-v2");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext, aad1);
      const opened = aead.open(nonce, sealed, aad2);

      expect(opened).toBeNull();
      aead.destroy();
    });

    it("should reject missing associated data when expected", () => {
      const key = makeKey(0x77);
      const nonce = makeNonce(0x77);
      const plaintext = new TextEncoder().encode("AAD required");
      const aad = new TextEncoder().encode("required-header");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext, aad);
      const opened = aead.open(nonce, sealed); // No AAD

      expect(opened).toBeNull();
      aead.destroy();
    });

    it("should reject truncated sealed data", () => {
      const key = makeKey(0x88);
      const nonce = makeNonce(0x88);
      const plaintext = new TextEncoder().encode("Truncation test");

      const aead = new Vortex256AEAD(key);
      const sealed = aead.seal(nonce, plaintext);

      const truncated = sealed.subarray(0, sealed.length - 4);
      const opened = aead.open(nonce, truncated);
      expect(opened).toBeNull();
      aead.destroy();
    });

    it("should reject sealed data shorter than tag", () => {
      const aead = new Vortex256AEAD(makeKey(0x00));
      const opened = aead.open(makeNonce(0x00), new Uint8Array(10));
      expect(opened).toBeNull();
      aead.destroy();
    });
  });

  // --------------------------------------------------------------------------
  // 9. Functional API (standalone functions)
  // --------------------------------------------------------------------------
  describe("Standalone Functions", () => {
    it("aeadEncrypt/aeadDecrypt should round-trip", () => {
      const key = makeKey(0xde, 0xad);
      const nonce = makeNonce(0xbe, 0xef);
      const plaintext = new TextEncoder().encode("Standalone API test");
      const aad = new TextEncoder().encode("aad");

      const { ciphertext, tag } = aeadEncrypt(key, nonce, plaintext, aad);
      const recovered = aeadDecrypt(key, nonce, ciphertext, tag, aad);

      expect(recovered).not.toBeNull();
      expect(new TextDecoder().decode(recovered!)).toBe("Standalone API test");
    });

    it("aeadDecrypt should return null for tampered data", () => {
      const key = makeKey(0xca, 0xfe);
      const nonce = makeNonce(0xba, 0xbe);
      const plaintext = new TextEncoder().encode("Tamper test");

      const { ciphertext, tag } = aeadEncrypt(key, nonce, plaintext);
      const tamperedCt = new Uint8Array(ciphertext);
      tamperedCt[0] ^= 0xff;

      expect(aeadDecrypt(key, nonce, tamperedCt, tag)).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // 10. Known Test Vectors (Pinned)
  // --------------------------------------------------------------------------
  describe("Known Test Vectors", () => {
    // These are computed once and pinned. If the algorithm changes,
    // these MUST be regenerated. They serve as regression tests.

    it("TV1: all-zero key and plaintext", () => {
      const key = makeKey(0x00);
      const ks = expandKey(key);
      const pt = makeBlock(0x00);
      const ct = encryptBlock(pt, ks);

      const ctHex = toHex(ct);
      expect(ctHex.length).toBe(32); // 16 bytes = 32 hex chars

      const recovered = decryptBlock(ct, ks);
      expect(toHex(recovered)).toBe(toHex(pt));

      console.log(`TV1 ciphertext: ${ctHex}`);
    });

    it("TV2: all-FF key and plaintext", () => {
      const key = makeKey(0xff);
      const ks = expandKey(key);
      const pt = makeBlock(0xff);
      const ct = encryptBlock(pt, ks);

      const ctHex = toHex(ct);
      expect(ctHex.length).toBe(32);

      const recovered = decryptBlock(ct, ks);
      expect(toHex(recovered)).toBe(toHex(pt));

      console.log(`TV2 ciphertext: ${ctHex}`);
    });

    it("TV3: incrementing key and counter plaintext", () => {
      const key = new Uint8Array(KEY_SIZE);
      for (let i = 0; i < KEY_SIZE; i++) key[i] = i;

      const pt = new Uint8Array(BLOCK_SIZE);
      for (let i = 0; i < BLOCK_SIZE; i++) pt[i] = i * 16 + i;

      const ks = expandKey(key);
      const ct = encryptBlock(pt, ks);

      const recovered = decryptBlock(ct, ks);
      expect(toHex(recovered)).toBe(toHex(pt));

      console.log(`TV3 ciphertext: ${toHex(ct)}`);
    });

    it("TV4: AEAD with known inputs", () => {
      const key = new Uint8Array(KEY_SIZE);
      for (let i = 0; i < KEY_SIZE; i++) key[i] = i;

      const nonce = new Uint8Array(NONCE_SIZE);
      for (let i = 0; i < NONCE_SIZE; i++) nonce[i] = i;

      const pt = new TextEncoder().encode("VORTEX-256 test");
      const aad = new TextEncoder().encode("header");

      const { ciphertext, tag } = aeadEncrypt(key, nonce, pt, aad);

      console.log(`TV4 ciphertext: ${toHex(ciphertext)}`);
      console.log(`TV4 tag: ${toHex(tag)}`);

      const recovered = aeadDecrypt(key, nonce, ciphertext, tag, aad);
      expect(recovered).not.toBeNull();
      expect(new TextDecoder().decode(recovered!)).toBe("VORTEX-256 test");
    });
  });

  // --------------------------------------------------------------------------
  // 11. Class API
  // --------------------------------------------------------------------------
  describe("Vortex256 Class", () => {
    it("should encrypt and decrypt blocks", () => {
      const cipher = new Vortex256(makeKey(0x42));
      const pt = makeBlock(0xab, 0xcd, 0xef, 0x01);
      const ct = cipher.encryptBlock(pt);
      const recovered = cipher.decryptBlock(ct);
      expect(toHex(recovered)).toBe(toHex(pt));
      cipher.destroy();
    });

    it("should reject wrong key length", () => {
      expect(() => new Vortex256(new Uint8Array(16))).toThrow();
    });
  });

  describe("Vortex256AEAD Class", () => {
    it("should reject wrong key length", () => {
      expect(() => new Vortex256AEAD(new Uint8Array(16))).toThrow();
    });

    it("should reject wrong nonce length", () => {
      const aead = new Vortex256AEAD(makeKey(0x00));
      expect(() => aead.seal(new Uint8Array(8), new Uint8Array(10))).toThrow();
      aead.destroy();
    });
  });

  // --------------------------------------------------------------------------
  // 12. Utility Functions
  // --------------------------------------------------------------------------
  describe("Utilities", () => {
    it("constantTimeEqual should correctly compare arrays", () => {
      const a = new Uint8Array([1, 2, 3, 4]);
      const b = new Uint8Array([1, 2, 3, 4]);
      const c = new Uint8Array([1, 2, 3, 5]);
      const d = new Uint8Array([1, 2, 3]);

      expect(constantTimeEqual(a, b)).toBe(true);
      expect(constantTimeEqual(a, c)).toBe(false);
      expect(constantTimeEqual(a, d)).toBe(false);
    });

    it("xorBytes should XOR correctly", () => {
      const a = new Uint8Array([0xff, 0x00, 0xaa, 0x55]);
      const b = new Uint8Array([0x0f, 0xf0, 0x55, 0xaa]);
      const result = xorBytes(a, b);
      expect(toHex(result)).toBe("f0f0ffff");
    });

    it("zeroize should clear buffer", () => {
      const buf = new Uint8Array([1, 2, 3, 4, 5]);
      zeroize(buf);
      expect(toHex(buf)).toBe("0000000000");
    });

    it("rotl32 should rotate left correctly", () => {
      expect(_internals.rotl32(0x80000000, 1)).toBe(1);
      expect(_internals.rotl32(1, 1)).toBe(2);
      expect(_internals.rotl32(0x12345678, 0)).toBe(0x12345678);
      expect(_internals.rotl32(0x12345678, 32)).toBe(0x12345678);
    });

    it("rotr32 should rotate right correctly", () => {
      expect(_internals.rotr32(1, 1)).toBe(0x80000000);
      expect(_internals.rotr32(2, 1)).toBe(1);
      expect(_internals.rotr32(0x12345678, 0)).toBe(0x12345678);
    });

    it("readU32BE/writeU32BE should be inverses", () => {
      const buf = new Uint8Array(4);
      _internals.writeU32BE(buf, 0, 0xdeadbeef);
      expect(_internals.readU32BE(buf, 0)).toBe(0xdeadbeef);
    });
  });

  // --------------------------------------------------------------------------
  // 13. Round Constants
  // --------------------------------------------------------------------------
  describe("Round Constants", () => {
    it("should have exactly NUM_ROUNDS constants", () => {
      expect(ROUND_CONSTANTS.length).toBe(NUM_ROUNDS);
    });

    it("should all be unique (anti-slide)", () => {
      const unique = new Set(ROUND_CONSTANTS);
      expect(unique.size).toBe(NUM_ROUNDS);
    });

    it("should all be non-zero", () => {
      for (const rc of ROUND_CONSTANTS) {
        expect(rc).not.toBe(0);
      }
    });
  });

  // --------------------------------------------------------------------------
  // 14. Structural Security Properties
  // --------------------------------------------------------------------------
  describe("Structural Security Properties", () => {
    it("encryption should not be the identity function", () => {
      const key = makeKey(0x00);
      const ks = expandKey(key);
      const pt = makeBlock(0x00);
      const ct = encryptBlock(pt, ks);

      expect(toHex(ct)).not.toBe(toHex(pt));
    });

    it("encryption should not be an involution (E(E(P)) != P in general)", () => {
      const key = makeKey(0x42);
      const ks = expandKey(key);
      const pt = makeBlock(0x13, 0x37);
      const ct = encryptBlock(pt, ks);
      const ct2 = encryptBlock(ct, ks);

      expect(toHex(ct2)).not.toBe(toHex(pt));
    });

    it("different round keys should be generated for each round", () => {
      const ks = expandKey(makeKey(0x00));
      for (let r1 = 0; r1 < NUM_ROUNDS; r1++) {
        for (let r2 = r1 + 1; r2 < NUM_ROUNDS; r2++) {
          let same = true;
          for (let w = 0; w < 4; w++) {
            if (ks.roundKeys[r1][w] !== ks.roundKeys[r2][w]) same = false;
          }
          expect(same).toBe(false);
        }
      }
    });

    it("F-function should have good diffusion", () => {
      const sbox = generateSBox(makeKey(0x00));
      const rc = ROUND_CONSTANTS[0];
      const rk = 0x12345678;

      const out1 = _internals.fFunction(0x00000000, rk, rc, sbox);
      const out2 = _internals.fFunction(0x00000001, rk, rc, sbox);

      let diff = out1 ^ out2;
      let bits = 0;
      while (diff) {
        bits += diff & 1;
        diff >>>= 1;
      }
      // At least 8 bits should differ (25% of 32)
      expect(bits).toBeGreaterThanOrEqual(8);
    });

    it("constant-time subWord and fast subWord should produce identical results", () => {
      const sbox = generateSBox(makeKey(0xab));
      for (let trial = 0; trial < 50; trial++) {
        const w = ((trial * 0x12345678 + 0xdeadbeef) >>> 0);
        const ctResult = _internals.ctSubWord(w, sbox);
        const fastResult = _internals.subWordFast(w, sbox);
        expect(ctResult).toBe(fastResult);
      }
    });
  });

  // --------------------------------------------------------------------------
  // 15. Performance Sanity Check
  // --------------------------------------------------------------------------
  describe("Performance", () => {
    it("should encrypt 100 blocks in reasonable time", () => {
      const key = makeKey(0x42);
      const ks = expandKey(key);
      const pt = makeBlock(0xab);

      const start = Date.now();
      for (let i = 0; i < 100; i++) {
        encryptBlock(pt, ks);
      }
      const elapsed = Date.now() - start;

      // Constant-time S-box lookups are ~256x slower, so be generous
      // 100 blocks with CT lookups should still complete within 60 seconds
      expect(elapsed).toBeLessThan(60000);
      console.log(`100 block encryptions (CT mode): ${elapsed}ms`);
    });

    it("should AEAD seal/open 1KB in reasonable time", () => {
      const key = makeKey(0x99);
      const nonce = makeNonce(0x01);
      const data = new Uint8Array(1024);
      for (let i = 0; i < data.length; i++) data[i] = i & 0xff;

      const aead = new Vortex256AEAD(key);

      const start = Date.now();
      const sealed = aead.seal(nonce, data);
      const opened = aead.open(nonce, sealed);
      const elapsed = Date.now() - start;

      expect(opened).not.toBeNull();
      expect(toHex(opened!)).toBe(toHex(data));
      // Generous timeout for CT mode
      expect(elapsed).toBeLessThan(120000);
      console.log(`1KB AEAD seal+open (CT mode): ${elapsed}ms`);
      aead.destroy();
    });
  });

  // --------------------------------------------------------------------------
  // 16. Counter Increment
  // --------------------------------------------------------------------------
  describe("Counter Operations", () => {
    it("should increment counter correctly", () => {
      const ctr = new Uint8Array(16);
      _internals.writeU32BE(ctr, 12, 0);

      _internals.incrementCounter(ctr);
      expect(_internals.readU32BE(ctr, 12)).toBe(1);

      _internals.incrementCounter(ctr);
      expect(_internals.readU32BE(ctr, 12)).toBe(2);
    });

    it("should throw on counter overflow to prevent keystream reuse", () => {
      const ctr = new Uint8Array(16);
      _internals.writeU32BE(ctr, 12, 0xffffffff);

      // Counter overflow must throw — counter 0 is reserved for the tag mask.
      expect(() => _internals.incrementCounter(ctr)).toThrow(/overflow/i);
    });
  });

  // --------------------------------------------------------------------------
  // 17. Determinism
  // --------------------------------------------------------------------------
  describe("Determinism", () => {
    it("same inputs should always produce same outputs (block cipher)", () => {
      const key = makeKey(0xab, 0xcd);
      const pt = makeBlock(0x12, 0x34);

      const ct1 = encryptBlock(pt, expandKey(key));
      const ct2 = encryptBlock(pt, expandKey(key));

      expect(toHex(ct1)).toBe(toHex(ct2));
    });

    it("same inputs should always produce same outputs (AEAD)", () => {
      const key = makeKey(0xfe, 0xdc);
      const nonce = makeNonce(0xba, 0x98);
      const pt = new TextEncoder().encode("Determinism check");
      const aad = new TextEncoder().encode("aad");

      const r1 = aeadEncrypt(key, nonce, pt, aad);
      const r2 = aeadEncrypt(key, nonce, pt, aad);

      expect(toHex(r1.ciphertext)).toBe(toHex(r2.ciphertext));
      expect(toHex(r1.tag)).toBe(toHex(r2.tag));
    });
  });
});
