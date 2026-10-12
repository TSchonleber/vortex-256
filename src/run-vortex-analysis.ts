/**
 * VORTEX-256 Attack Analysis Runner
 * ==================================
 * Bridge between the VORTEX-256 cipher and the attack suite.
 * Implements CipherUnderTest interface and runs the full analysis.
 *
 * Usage: npx tsx src/run-vortex-analysis.ts
 */

import {
  type CipherUnderTest,
  runFullAttackSuite,
} from "./vortex-attack-suite";
import {
  _internals,
  BLOCK_SIZE,
  decryptBlock,
  encryptBlock,
  expandKey,
  generateSBox,
  KEY_SIZE,
  NUM_ROUNDS,
} from "./vortex-cipher";

// ---------------------------------------------------------------------------
// CipherUnderTest adapter for VORTEX-256
// ---------------------------------------------------------------------------

const vortexAdapter: CipherUnderTest = {
  name: "VORTEX-256",
  blockBytes: BLOCK_SIZE,
  keyBytes: KEY_SIZE,
  rounds: NUM_ROUNDS,

  encrypt(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
    const ks = expandKey(key);
    return encryptBlock(plaintext, ks);
  },

  decrypt(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
    const ks = expandKey(key);
    return decryptBlock(ciphertext, ks);
  },

  encryptRounds(plaintext: Uint8Array, key: Uint8Array, rounds: number): Uint8Array {
    // Replicate the encrypt path from vortex-cipher.ts but with variable round count.
    const ks = expandKey(key);

    // Parse block into 4 x 32-bit words
    const state = new Uint32Array(4);
    for (let i = 0; i < 4; i++) {
      state[i] = _internals.readU32BE(plaintext, i * 4);
    }

    // Pre-whitening
    for (let i = 0; i < 4; i++) {
      state[i] = (state[i] ^ ks.preWhitening[i]) >>> 0;
    }

    // Apply reduced rounds
    const effectiveRounds = Math.min(rounds, NUM_ROUNDS);
    for (let r = 0; r < effectiveRounds; r++) {
      _internals.vortexRound(state, ks.roundKeys[r], r, ks.sbox);
    }

    // Post-whitening (only if full rounds)
    if (rounds >= NUM_ROUNDS) {
      for (let i = 0; i < 4; i++) {
        state[i] = (state[i] ^ ks.postWhitening[i]) >>> 0;
      }
    }

    // Serialize
    const out = new Uint8Array(BLOCK_SIZE);
    for (let i = 0; i < 4; i++) {
      _internals.writeU32BE(out, i * 4, state[i]);
    }
    return out;
  },

  getSBoxes(key: Uint8Array): number[][] {
    const sbox = generateSBox(key);
    // VORTEX-256 uses a single key-dependent S-box
    return [Array.from(sbox)];
  },

  deriveSubkeys(key: Uint8Array): Uint8Array[] {
    const ks = expandKey(key);
    // Return round keys as Uint8Array (each is 4 x 32-bit = 16 bytes)
    const subkeys: Uint8Array[] = [];

    // Pre-whitening key
    const preWK = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      _internals.writeU32BE(preWK, i * 4, ks.preWhitening[i]);
    }
    subkeys.push(preWK);

    // Round keys
    for (let r = 0; r < NUM_ROUNDS; r++) {
      const rkBytes = new Uint8Array(16);
      for (let i = 0; i < 4; i++) {
        _internals.writeU32BE(rkBytes, i * 4, ks.roundKeys[r][i]);
      }
      subkeys.push(rkBytes);
    }

    // Post-whitening key
    const postWK = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      _internals.writeU32BE(postWK, i * 4, ks.postWhitening[i]);
    }
    subkeys.push(postWK);

    return subkeys;
  },
};

// ---------------------------------------------------------------------------
// Run the analysis
// ---------------------------------------------------------------------------

async function main() {
  console.log("Starting VORTEX-256 cryptanalysis...\n");

  const { results, summary, verdict } = await runFullAttackSuite(vortexAdapter);

  // Output structured results for post-processing
  console.log("\n--- RAW RESULTS (JSON) ---");
  console.log(JSON.stringify(
    results.map(r => ({
      name: r.name,
      category: r.category,
      passed: r.passed,
      score: r.score,
      threshold: r.threshold,
      severity: r.severity,
      details: r.details,
    })),
    null,
    2
  ));

  // Exit with non-zero if broken
  if (verdict === "BROKEN") process.exit(2);
  if (verdict === "WEAK") process.exit(1);
  process.exit(0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(99);
});
