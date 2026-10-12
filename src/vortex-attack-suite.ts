/**
 * VORTEX-256 Attack Analysis Framework
 * =====================================
 * A brutal, comprehensive cryptanalytic test suite for evaluating
 * custom symmetric block ciphers.
 *
 * Target spec: 256-bit key, 128-bit block, 16+ rounds,
 *              4-branch generalized Feistel, key-dependent S-boxes, AEAD.
 *
 * Purpose: Educational / research — red-team a cipher before it ships.
 *
 * Usage:
 *   1. Implement the CipherUnderTest interface for VORTEX-256.
 *   2. Call `runFullAttackSuite(cipher)`.
 *   3. Anything that says FAIL is a real problem.
 */

// ---------------------------------------------------------------------------
// 0. Types & Interface
// ---------------------------------------------------------------------------

/** The cipher must expose these hooks so we can attack it. */
export interface CipherUnderTest {
  /** Human-readable name, e.g. "VORTEX-256" */
  readonly name: string;

  /** Block size in bytes (expect 16 for 128-bit block). */
  readonly blockBytes: number;

  /** Key size in bytes (expect 32 for 256-bit key). */
  readonly keyBytes: number;

  /** Total number of rounds. */
  readonly rounds: number;

  /**
   * Core encryption: single block, full rounds.
   * plaintext and key are Uint8Array of the correct lengths.
   * Returns ciphertext as Uint8Array.
   */
  encrypt(plaintext: Uint8Array, key: Uint8Array): Uint8Array;

  /**
   * Core decryption: single block, full rounds.
   */
  decrypt(ciphertext: Uint8Array, key: Uint8Array): Uint8Array;

  /**
   * Round-reduced encryption. `rounds` = how many rounds to run.
   * Essential for differential / linear analysis on reduced variants.
   * If not feasible, throw — the framework will skip those tests.
   */
  encryptRounds(plaintext: Uint8Array, key: Uint8Array, rounds: number): Uint8Array;

  /**
   * Expose the S-box(es) used by the cipher.
   * Each S-box is a lookup table: input byte -> output byte (256 entries).
   * For key-dependent S-boxes, generate them for a given key.
   * Return an array of S-boxes (one per distinct S-box in the round function).
   */
  getSBoxes(key: Uint8Array): number[][];

  /**
   * Derive the round subkeys from the master key.
   * Returns an array of subkeys (one per round), each a Uint8Array.
   */
  deriveSubkeys(key: Uint8Array): Uint8Array[];
}

/** Verdict for each test. */
export interface TestResult {
  name: string;
  category: string;
  passed: boolean;
  score: number;       // 0.0 – 1.0 (1 = ideal)
  threshold: number;   // minimum acceptable score
  details: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

// ---------------------------------------------------------------------------
// 1. Utility helpers
// ---------------------------------------------------------------------------

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  // Use crypto.getRandomValues in browser or Node 19+, else fallback
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    // getRandomValues has a 65536-byte per-call limit — chunk if needed
    const CHUNK = 65536;
    for (let offset = 0; offset < n; offset += CHUNK) {
      const end = Math.min(offset + CHUNK, n);
      globalThis.crypto.getRandomValues(buf.subarray(offset, end));
    }
  } else {
    for (let i = 0; i < n; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return buf;
}

function clone(a: Uint8Array): Uint8Array {
  return new Uint8Array(a);
}

function flipBit(data: Uint8Array, bitIndex: number): Uint8Array {
  const out = clone(data);
  const byteIdx = bitIndex >>> 3;
  const bitIdx = bitIndex & 7;
  out[byteIdx] ^= (1 << bitIdx);
  return out;
}

function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  let dist = 0;
  for (let i = 0; i < a.length; i++) {
    let xor = a[i] ^ b[i];
    while (xor) { dist += xor & 1; xor >>>= 1; }
  }
  return dist;
}

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function isZero(a: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) if (a[i] !== 0) return false;
  return true;
}

/** Chi-squared test against uniform distribution over bytes. */
function chiSquaredBytes(data: Uint8Array): number {
  const counts = new Float64Array(256);
  for (let i = 0; i < data.length; i++) counts[data[i]]++;
  const expected = data.length / 256;
  let chi2 = 0;
  for (let i = 0; i < 256; i++) {
    const diff = counts[i] - expected;
    chi2 += (diff * diff) / expected;
  }
  return chi2;
}

/** Monobit frequency test (NIST SP 800-22 style). */
function frequencyTest(data: Uint8Array): number {
  let ones = 0;
  const totalBits = data.length * 8;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    while (b) { ones += b & 1; b >>>= 1; }
  }
  // S_obs = |sum| / sqrt(n)  where sum = 2*ones - n
  const sum = 2 * ones - totalBits;
  const sObs = Math.abs(sum) / Math.sqrt(totalBits);
  // p-value approximation: erfc(sObs / sqrt(2))
  return erfc(sObs / Math.SQRT2);
}

/** Runs test — tests oscillation between 0 and 1 bits. */
function runsTest(data: Uint8Array): number {
  const totalBits = data.length * 8;
  let ones = 0;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    while (b) { ones += b & 1; b >>>= 1; }
  }
  const pi = ones / totalBits;
  // Pre-test: if |pi - 0.5| >= 2/sqrt(n), fail
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(totalBits)) return 0;

  // Count runs
  let runs = 1;
  let prevBit = (data[0] >> 0) & 1;
  for (let i = 0; i < data.length; i++) {
    for (let bit = 0; bit < 8; bit++) {
      if (i === 0 && bit === 0) continue;
      const curBit = (data[i] >> bit) & 1;
      if (curBit !== prevBit) runs++;
      prevBit = curBit;
    }
  }
  const num = Math.abs(runs - 2 * totalBits * pi * (1 - pi));
  const den = 2 * Math.sqrt(2 * totalBits) * pi * (1 - pi);
  return erfc(num / den);
}

/** Serial correlation coefficient. */
function serialCorrelation(data: Uint8Array): number {
  if (data.length < 2) return 0;
  const n = data.length;
  let sumX = 0, sumX2 = 0, sumXY = 0;
  for (let i = 0; i < n; i++) {
    sumX += data[i];
    sumX2 += data[i] * data[i];
    sumXY += data[i] * data[(i + 1) % n];
  }
  const mean = sumX / n;
  const num = (n * sumXY - sumX * sumX);
  const den = (n * sumX2 - sumX * sumX);
  if (den === 0) return 0;
  return num / den;  // should be close to 0 for random
}

/** Complementary error function (good enough approximation). */
function erfc(x: number): number {
  const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741;
  const a4 = -1.453152027, a5 = 1.061405429, p = 0.3275911;
  const sign = x < 0 ? -1 : 1;
  x = Math.abs(x);
  const t = 1.0 / (1.0 + p * x);
  const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
  return 1 - sign * y;
}

// ---------------------------------------------------------------------------
// 2. STATISTICAL ANALYSIS MODULE
// ---------------------------------------------------------------------------

function testAvalancheEffect(cipher: CipherUnderTest, samples: number = 200): TestResult {
  const blockBits = cipher.blockBytes * 8;
  const key = randomBytes(cipher.keyBytes);
  const idealFlips = blockBits / 2; // 50% of bits should flip
  let totalDeviation = 0;
  let worstDeviation = 0;
  let worstBit = -1;

  // Per-bit accumulator: for each input bit position, track average output changes
  const perBitFlips = new Float64Array(blockBits);
  const perBitCount = new Float64Array(blockBits);

  for (let s = 0; s < samples; s++) {
    const pt = randomBytes(cipher.blockBytes);
    const ct0 = cipher.encrypt(pt, key);

    for (let bit = 0; bit < blockBits; bit++) {
      const ptFlipped = flipBit(pt, bit);
      const ct1 = cipher.encrypt(ptFlipped, key);
      const dist = hammingDistance(ct0, ct1);
      perBitFlips[bit] += dist;
      perBitCount[bit]++;
    }
  }

  // Analyse
  for (let bit = 0; bit < blockBits; bit++) {
    const avg = perBitFlips[bit] / perBitCount[bit];
    const dev = Math.abs(avg - idealFlips) / idealFlips;
    totalDeviation += dev;
    if (dev > worstDeviation) {
      worstDeviation = dev;
      worstBit = bit;
    }
  }

  const avgDeviation = totalDeviation / blockBits;
  // Score: 1.0 if avgDeviation=0, 0.0 if avgDeviation>=0.15
  const score = Math.max(0, 1 - avgDeviation / 0.15);
  const passed = avgDeviation < 0.05 && worstDeviation < 0.15;

  return {
    name: 'Avalanche Effect',
    category: 'Statistical',
    passed,
    score,
    threshold: 0.67,
    details: `Avg deviation from 50%: ${(avgDeviation * 100).toFixed(2)}%, ` +
             `Worst bit ${worstBit}: ${(worstDeviation * 100).toFixed(2)}% deviation. ` +
             `${samples} samples x ${blockBits} bit flips.`,
    severity: passed ? 'info' : 'critical',
  };
}

function testSAC(cipher: CipherUnderTest, samples: number = 300): TestResult {
  // Strict Avalanche Criterion: flipping any single input bit should cause
  // each output bit to flip with probability 0.5.
  const blockBits = cipher.blockBytes * 8;
  const key = randomBytes(cipher.keyBytes);

  // matrix[inputBit][outputBit] = count of flips
  const matrix: number[][] = [];
  for (let i = 0; i < blockBits; i++) matrix[i] = new Array(blockBits).fill(0);

  for (let s = 0; s < samples; s++) {
    const pt = randomBytes(cipher.blockBytes);
    const ct0 = cipher.encrypt(pt, key);

    for (let inBit = 0; inBit < blockBits; inBit++) {
      const ptFlipped = flipBit(pt, inBit);
      const ct1 = cipher.encrypt(ptFlipped, key);
      for (let outBit = 0; outBit < blockBits; outBit++) {
        const byte0 = ct0[outBit >>> 3];
        const byte1 = ct1[outBit >>> 3];
        const bit0 = (byte0 >> (outBit & 7)) & 1;
        const bit1 = (byte1 >> (outBit & 7)) & 1;
        if (bit0 !== bit1) matrix[inBit][outBit]++;
      }
    }
  }

  // Each cell should be ~samples/2. Measure max deviation.
  let maxDev = 0;
  let totalDev = 0;
  let count = 0;
  for (let i = 0; i < blockBits; i++) {
    for (let j = 0; j < blockBits; j++) {
      const prob = matrix[i][j] / samples;
      const dev = Math.abs(prob - 0.5);
      totalDev += dev;
      count++;
      if (dev > maxDev) maxDev = dev;
    }
  }
  const avgDev = totalDev / count;
  const passed = avgDev < 0.05 && maxDev < 0.20;
  const score = Math.max(0, 1 - avgDev / 0.10);

  return {
    name: 'Strict Avalanche Criterion (SAC)',
    category: 'Statistical',
    passed,
    score,
    threshold: 0.50,
    details: `Avg |P(flip)-0.5|: ${avgDev.toFixed(4)}, Max deviation: ${maxDev.toFixed(4)}. ` +
             `Matrix: ${blockBits}x${blockBits} over ${samples} samples.`,
    severity: passed ? 'info' : 'critical',
  };
}

function testBIC(cipher: CipherUnderTest, samples: number = 500): TestResult {
  // Bit Independence Criterion: for each input bit flip, all pairs of output
  // bit changes should be independent (correlation near zero).
  const blockBits = cipher.blockBytes * 8;
  const key = randomBytes(cipher.keyBytes);

  // Sample a subset of input bits to keep runtime sane
  const inputBitsSampled = Math.min(blockBits, 32);
  const inputBits: number[] = [];
  for (let i = 0; i < inputBitsSampled; i++) {
    inputBits.push(Math.floor(i * blockBits / inputBitsSampled));
  }

  // For each sampled input bit, collect output difference vectors
  let maxCorrelation = 0;
  let totalCorrelation = 0;
  let pairCount = 0;

  for (const inBit of inputBits) {
    // Collect bit-change vectors
    const changes: number[][] = []; // changes[sample][outBit] = 0 or 1
    for (let s = 0; s < samples; s++) {
      const pt = randomBytes(cipher.blockBytes);
      const ct0 = cipher.encrypt(pt, key);
      const ct1 = cipher.encrypt(flipBit(pt, inBit), key);
      const diff: number[] = [];
      for (let ob = 0; ob < blockBits; ob++) {
        const b0 = (ct0[ob >>> 3] >> (ob & 7)) & 1;
        const b1 = (ct1[ob >>> 3] >> (ob & 7)) & 1;
        diff.push(b0 ^ b1);
      }
      changes.push(diff);
    }

    // Check pairwise correlation between output bit columns
    // Sample pairs to keep O(n^2) manageable
    const pairSample = Math.min(blockBits, 32);
    for (let a = 0; a < pairSample; a++) {
      for (let b = a + 1; b < pairSample; b++) {
        const oa = Math.floor(a * blockBits / pairSample);
        const ob = Math.floor(b * blockBits / pairSample);
        // Compute correlation between column oa and column ob
        let n11 = 0, n10 = 0, n01 = 0, n00 = 0;
        for (let s = 0; s < samples; s++) {
          const va = changes[s][oa];
          const vb = changes[s][ob];
          if (va && vb) n11++;
          else if (va && !vb) n10++;
          else if (!va && vb) n01++;
          else n00++;
        }
        // Phi coefficient
        const num = n11 * n00 - n10 * n01;
        const den = Math.sqrt((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00));
        const corr = den === 0 ? 0 : Math.abs(num / den);
        totalCorrelation += corr;
        pairCount++;
        if (corr > maxCorrelation) maxCorrelation = corr;
      }
    }
  }

  const avgCorr = pairCount > 0 ? totalCorrelation / pairCount : 0;
  const passed = avgCorr < 0.10 && maxCorrelation < 0.30;
  const score = Math.max(0, 1 - avgCorr / 0.15);

  return {
    name: 'Bit Independence Criterion (BIC)',
    category: 'Statistical',
    passed,
    score,
    threshold: 0.33,
    details: `Avg pairwise |correlation|: ${avgCorr.toFixed(4)}, ` +
             `Max: ${maxCorrelation.toFixed(4)}. ` +
             `${pairCount} output-bit pairs, ${inputBitsSampled} input bits, ${samples} samples.`,
    severity: passed ? 'info' : 'high',
  };
}

function testOutputRandomness(cipher: CipherUnderTest, samples: number = 2000): TestResult {
  const key = randomBytes(cipher.keyBytes);

  // Encrypt sequential plaintexts (worst case for randomness)
  const allCiphertext = new Uint8Array(samples * cipher.blockBytes);
  for (let i = 0; i < samples; i++) {
    const pt = new Uint8Array(cipher.blockBytes);
    // Counter mode-style sequential input
    pt[0] = i & 0xff;
    pt[1] = (i >> 8) & 0xff;
    pt[2] = (i >> 16) & 0xff;
    pt[3] = (i >> 24) & 0xff;
    const ct = cipher.encrypt(pt, key);
    allCiphertext.set(ct, i * cipher.blockBytes);
  }

  // Run battery
  const chi2 = chiSquaredBytes(allCiphertext);
  // For 255 DOF, critical value at alpha=0.01 is ~310
  const chi2Pass = chi2 < 310;

  const freqP = frequencyTest(allCiphertext);
  const freqPass = freqP > 0.01;

  const runsP = runsTest(allCiphertext);
  const runsPass = runsP > 0.01;

  const sc = serialCorrelation(allCiphertext);
  const scPass = Math.abs(sc) < 0.02;

  const allPass = chi2Pass && freqPass && runsPass && scPass;
  const passCount = [chi2Pass, freqPass, runsPass, scPass].filter(Boolean).length;
  const score = passCount / 4;

  return {
    name: 'Output Randomness Battery',
    category: 'Statistical',
    passed: allPass,
    score,
    threshold: 0.75,
    details: `Chi2=${chi2.toFixed(1)} (${chi2Pass ? 'OK' : 'FAIL'}), ` +
             `Freq p=${freqP.toFixed(4)} (${freqPass ? 'OK' : 'FAIL'}), ` +
             `Runs p=${runsP.toFixed(4)} (${runsPass ? 'OK' : 'FAIL'}), ` +
             `SerialCorr=${sc.toFixed(6)} (${scPass ? 'OK' : 'FAIL'}). ` +
             `${samples} sequential plaintexts.`,
    severity: allPass ? 'info' : 'high',
  };
}

// ---------------------------------------------------------------------------
// 3. DIFFERENTIAL CRYPTANALYSIS
// ---------------------------------------------------------------------------

function buildDifferentialDistributionTable(sbox: number[]): number[][] {
  // DDT[inputDiff][outputDiff] = count
  const size = sbox.length; // 256 for 8-bit S-box
  const ddt: number[][] = [];
  for (let i = 0; i < size; i++) ddt[i] = new Array(size).fill(0);

  for (let x = 0; x < size; x++) {
    for (let dx = 0; dx < size; dx++) {
      const dy = sbox[x] ^ sbox[x ^ dx];
      ddt[dx][dy]++;
    }
  }
  return ddt;
}

function testDifferentialSBoxes(cipher: CipherUnderTest): TestResult {
  const key = randomBytes(cipher.keyBytes);
  let sboxes: number[][];
  try {
    sboxes = cipher.getSBoxes(key);
  } catch {
    return {
      name: 'S-Box Differential Distribution',
      category: 'Differential',
      passed: false,
      score: 0,
      threshold: 0.50,
      details: 'SKIPPED: getSBoxes() not available.',
      severity: 'info',
    };
  }

  let worstMaxProb = 0;
  let worstSBox = -1;
  const sboxResults: string[] = [];

  for (let si = 0; si < sboxes.length; si++) {
    const ddt = buildDifferentialDistributionTable(sboxes[si]);
    const size = sboxes[si].length;

    // Find maximum differential probability (excluding trivial 0->0)
    let maxCount = 0;
    let maxDx = 0, maxDy = 0;
    for (let dx = 1; dx < size; dx++) {
      for (let dy = 0; dy < size; dy++) {
        if (ddt[dx][dy] > maxCount) {
          maxCount = ddt[dx][dy];
          maxDx = dx;
          maxDy = dy;
        }
      }
    }
    const prob = maxCount / size;
    if (prob > worstMaxProb) {
      worstMaxProb = prob;
      worstSBox = si;
    }

    // Check for fixed points and structural weaknesses
    let fixedPoints = 0;
    for (let x = 0; x < size; x++) {
      if (sboxes[si][x] === x) fixedPoints++;
    }

    sboxResults.push(
      `S${si}: max_dp=${prob.toFixed(4)} (dx=0x${maxDx.toString(16)},dy=0x${maxDy.toString(16)}), ` +
      `fixed_pts=${fixedPoints}`
    );
  }

  // AES S-box has max differential probability 4/256 = 0.015625
  // Anything above 6/256 ~ 0.023 is concerning. Above 10/256 ~ 0.039 is bad.
  const passed = worstMaxProb <= 6 / 256;
  const score = Math.max(0, 1 - (worstMaxProb - 4 / 256) / (16 / 256));

  return {
    name: 'S-Box Differential Distribution',
    category: 'Differential',
    passed,
    score,
    threshold: 0.50,
    details: `Worst S-box ${worstSBox}: max_dp=${worstMaxProb.toFixed(6)}. ` +
             `AES baseline: ${(4 / 256).toFixed(6)}. ` +
             sboxResults.join(' | '),
    severity: passed ? 'info' : 'critical',
  };
}

function testDifferentialPropagation(cipher: CipherUnderTest, maxTestRounds: number = 6): TestResult {
  // Track how well input differences propagate through reduced rounds.
  // A good cipher should diffuse differences rapidly.
  const key = randomBytes(cipher.keyBytes);
  const blockBits = cipher.blockBytes * 8;
  const samples = 500;
  const roundResults: string[] = [];
  let worstBias = 0;
  let worstBiasR2Plus = 0; // worst bias excluding round 1 (GFN-4 has inherent slow R1 diffusion)

  for (let r = 1; r <= Math.min(maxTestRounds, cipher.rounds); r++) {
    // Try single-bit differences — does the output look random after r rounds?
    let totalHamming = 0;
    let minHamming = blockBits;
    let maxHamming = 0;

    for (let s = 0; s < samples; s++) {
      const pt = randomBytes(cipher.blockBytes);
      const bit = Math.floor(Math.random() * blockBits);
      const ptMod = flipBit(pt, bit);

      let ct0: Uint8Array, ct1: Uint8Array;
      try {
        ct0 = cipher.encryptRounds(pt, key, r);
        ct1 = cipher.encryptRounds(ptMod, key, r);
      } catch {
        roundResults.push(`R${r}: SKIPPED (encryptRounds not supported)`);
        continue;
      }

      const hd = hammingDistance(ct0, ct1);
      totalHamming += hd;
      minHamming = Math.min(minHamming, hd);
      maxHamming = Math.max(maxHamming, hd);
    }

    const avgHamming = totalHamming / samples;
    const idealHamming = blockBits / 2;
    const bias = Math.abs(avgHamming - idealHamming) / idealHamming;
    if (bias > worstBias) worstBias = bias;
    if (r >= 2 && bias > worstBiasR2Plus) worstBiasR2Plus = bias;

    roundResults.push(
      `R${r}: avg_hd=${avgHamming.toFixed(1)}/${blockBits} ` +
      `(${(avgHamming / blockBits * 100).toFixed(1)}%), ` +
      `min=${minHamming}, max=${maxHamming}, bias=${(bias * 100).toFixed(1)}%`
    );
  }

  // After 2+ rounds, bias should be very low. Round 1 slow diffusion is expected
  // for GFN-4 designs (only 2 of 4 branches are updated per round), so the pass/fail
  // threshold is based on the worst bias from round 2 onward.
  // We still report R1 data for informational purposes.
  const passed = worstBiasR2Plus < 0.10;
  const score = Math.max(0, 1 - worstBiasR2Plus / 0.20);

  return {
    name: 'Differential Propagation (Reduced Rounds)',
    category: 'Differential',
    passed,
    score,
    threshold: 0.50,
    details: roundResults.join(' || '),
    severity: passed ? 'info' : 'high',
  };
}

function testImpossibleDifferentials(cipher: CipherUnderTest): TestResult {
  // Look for input differences that NEVER produce certain output differences.
  // In a perfect random permutation with 128-bit blocks this is expected,
  // but if we find them for reduced rounds it hints at structural weakness.
  const key = randomBytes(cipher.keyBytes);
  const blockBytes = cipher.blockBytes;
  const samples = 5000;
  const maxRounds = Math.min(4, cipher.rounds);

  // Test: for each reduced round count, pick single-byte input differences
  // and check if any output-byte difference is never observed.
  const findings: string[] = [];
  let suspiciousCount = 0;

  for (let r = 1; r <= maxRounds; r++) {
    // Try difference at byte 0
    const outputByteSeen: Set<number>[] = [];
    for (let ob = 0; ob < blockBytes; ob++) {
      outputByteSeen.push(new Set());
    }

    for (let s = 0; s < samples; s++) {
      const pt = randomBytes(blockBytes);
      const ptMod = clone(pt);
      ptMod[0] ^= 0x01; // single-bit diff in byte 0

      let ct0: Uint8Array, ct1: Uint8Array;
      try {
        ct0 = cipher.encryptRounds(pt, key, r);
        ct1 = cipher.encryptRounds(ptMod, key, r);
      } catch {
        findings.push(`R${r}: SKIPPED`);
        continue;
      }

      for (let ob = 0; ob < blockBytes; ob++) {
        outputByteSeen[ob].add(ct0[ob] ^ ct1[ob]);
      }
    }

    // For each output byte, how many of 256 possible differences were seen?
    let minCoverage = 256;
    let minByte = -1;
    for (let ob = 0; ob < blockBytes; ob++) {
      if (outputByteSeen[ob].size < minCoverage) {
        minCoverage = outputByteSeen[ob].size;
        minByte = ob;
      }
    }

    // After enough samples with a single-bit input diff, we should see nearly all
    // output byte differences (if diffusion is good).
    // Low coverage = possible impossible differential or poor diffusion.
    const expectedMinCoverage = r >= 3 ? 200 : r >= 2 ? 100 : 20;
    if (minCoverage < expectedMinCoverage) {
      suspiciousCount++;
    }
    findings.push(`R${r}: min_output_byte_coverage=${minCoverage}/256 (byte ${minByte})`);
  }

  const passed = suspiciousCount === 0;
  const score = Math.max(0, 1 - suspiciousCount / maxRounds);

  return {
    name: 'Impossible Differential Detector',
    category: 'Differential',
    passed,
    score,
    threshold: 0.50,
    details: findings.join(' || ') +
             (suspiciousCount > 0 ? ` WARNING: ${suspiciousCount} suspicious round(s)` : ''),
    severity: passed ? 'info' : 'high',
  };
}

// ---------------------------------------------------------------------------
// 4. LINEAR CRYPTANALYSIS
// ---------------------------------------------------------------------------

function buildLinearApproximationTable(sbox: number[]): number[][] {
  // LAT[inputMask][outputMask] = bias count (centered: subtract size/2 for actual bias)
  const size = sbox.length;
  const lat: number[][] = [];
  for (let i = 0; i < size; i++) lat[i] = new Array(size).fill(0);

  for (let im = 0; im < size; im++) {
    for (let om = 0; om < size; om++) {
      let count = 0;
      for (let x = 0; x < size; x++) {
        // parity of (x & im) XOR parity of (sbox[x] & om)
        const inParity = popcount(x & im) & 1;
        const outParity = popcount(sbox[x] & om) & 1;
        if (inParity === outParity) count++;
      }
      lat[im][om] = count;
    }
  }
  return lat;
}

function popcount(x: number): number {
  let c = 0;
  while (x) { c += x & 1; x >>>= 1; }
  return c;
}

function testLinearSBoxes(cipher: CipherUnderTest): TestResult {
  const key = randomBytes(cipher.keyBytes);
  let sboxes: number[][];
  try {
    sboxes = cipher.getSBoxes(key);
  } catch {
    return {
      name: 'S-Box Linear Approximation',
      category: 'Linear',
      passed: false,
      score: 0,
      threshold: 0.50,
      details: 'SKIPPED: getSBoxes() not available.',
      severity: 'info',
    };
  }

  let worstBias = 0;
  let worstSBox = -1;
  const results: string[] = [];

  for (let si = 0; si < sboxes.length; si++) {
    const lat = buildLinearApproximationTable(sboxes[si]);
    const size = sboxes[si].length;
    const half = size / 2;

    let maxBias = 0;
    let maxIm = 0, maxOm = 0;
    for (let im = 1; im < size; im++) {
      for (let om = 1; om < size; om++) {
        const bias = Math.abs(lat[im][om] - half) / size;
        if (bias > maxBias) {
          maxBias = bias;
          maxIm = im;
          maxOm = om;
        }
      }
    }

    if (maxBias > worstBias) {
      worstBias = maxBias;
      worstSBox = si;
    }

    results.push(
      `S${si}: max_bias=${maxBias.toFixed(6)} ` +
      `(im=0x${maxIm.toString(16)},om=0x${maxOm.toString(16)})`
    );
  }

  // AES S-box has max linear bias 16/256 = 0.0625.
  // Anything above 0.10 is concerning.
  const passed = worstBias <= 0.0625 + 0.02;
  const score = Math.max(0, 1 - (worstBias - 0.0625) / 0.10);

  return {
    name: 'S-Box Linear Approximation Table',
    category: 'Linear',
    passed,
    score,
    threshold: 0.50,
    details: `Worst S-box ${worstSBox}: max_bias=${worstBias.toFixed(6)}. ` +
             `AES baseline: ${(16 / 256).toFixed(6)}. ` +
             results.join(' | '),
    severity: passed ? 'info' : 'critical',
  };
}

function testLinearBiasAccumulation(cipher: CipherUnderTest): TestResult {
  // Empirical: encrypt many random plaintexts, check if any linear relation
  // between plaintext and ciphertext bits holds with non-trivial bias.
  const key = randomBytes(cipher.keyBytes);
  const blockBits = cipher.blockBytes * 8;
  const samples = 10000;

  // Test a selection of input/output mask pairs
  const maskPairs: [number, number][] = [];
  // Single-bit masks
  for (let i = 0; i < Math.min(blockBits, 16); i++) {
    for (let j = 0; j < Math.min(blockBits, 16); j++) {
      maskPairs.push([i, j]);
    }
  }

  let maxBias = 0;
  let maxPair: [number, number] = [0, 0];

  // Collect plaintext/ciphertext pairs
  const pts: Uint8Array[] = [];
  const cts: Uint8Array[] = [];
  for (let s = 0; s < samples; s++) {
    const pt = randomBytes(cipher.blockBytes);
    pts.push(pt);
    cts.push(cipher.encrypt(pt, key));
  }

  for (const [ib, ob] of maskPairs) {
    let agree = 0;
    for (let s = 0; s < samples; s++) {
      const ptBit = (pts[s][ib >>> 3] >> (ib & 7)) & 1;
      const ctBit = (cts[s][ob >>> 3] >> (ob & 7)) & 1;
      if (ptBit === ctBit) agree++;
    }
    const bias = Math.abs(agree / samples - 0.5);
    if (bias > maxBias) {
      maxBias = bias;
      maxPair = [ib, ob];
    }
  }

  // For a 128-bit block cipher, any individual linear bias should be
  // negligible (< 2^-64 ideally). Empirically with 10k samples,
  // statistical noise gives bias up to ~0.01.
  const noiseFloor = 2 / Math.sqrt(samples); // ~0.02 for 10k samples
  const passed = maxBias < noiseFloor * 2;
  const score = Math.max(0, 1 - maxBias / (noiseFloor * 3));

  return {
    name: 'Linear Bias Accumulation (Full Rounds)',
    category: 'Linear',
    passed,
    score,
    threshold: 0.50,
    details: `Max empirical bias: ${maxBias.toFixed(6)} at pt_bit=${maxPair[0]},ct_bit=${maxPair[1]}. ` +
             `Noise floor: ~${noiseFloor.toFixed(6)}. ` +
             `${maskPairs.length} mask pairs, ${samples} samples.`,
    severity: passed ? 'info' : 'critical',
  };
}

// ---------------------------------------------------------------------------
// 5. ALGEBRAIC ANALYSIS
// ---------------------------------------------------------------------------

function computeAlgebraicDegree(sbox: number[]): number {
  // Compute the algebraic degree of the S-box as a vectorial Boolean function.
  // The algebraic degree is the maximum degree across all output bit ANFs.
  const n = Math.log2(sbox.length);
  if (!Number.isInteger(n)) return -1;
  const size = sbox.length;
  let maxDeg = 0;

  for (let outBit = 0; outBit < 8; outBit++) {
    // Extract the Boolean function for this output bit
    const f = new Int32Array(size);
    for (let x = 0; x < size; x++) {
      f[x] = (sbox[x] >> outBit) & 1;
    }

    // Mobius transform to get ANF
    const anf = new Int32Array(f);
    for (let i = 0; i < n; i++) {
      for (let x = 0; x < size; x++) {
        if (x & (1 << i)) {
          anf[x] ^= anf[x ^ (1 << i)];
        }
      }
    }

    // Degree = max Hamming weight of x where anf[x] = 1
    for (let x = 0; x < size; x++) {
      if (anf[x]) {
        const deg = popcount(x);
        if (deg > maxDeg) maxDeg = deg;
      }
    }
  }

  return maxDeg;
}

function computeNonlinearity(sbox: number[]): number {
  // Nonlinearity = min over all output bits of the minimum distance to affine functions.
  // NL = 2^(n-1) - max|Walsh coefficient| / 2
  const size = sbox.length;
  const n = Math.log2(size);
  let minNL = Infinity;

  for (let outBit = 0; outBit < 8; outBit++) {
    // Extract Boolean function
    const f = new Int32Array(size);
    for (let x = 0; x < size; x++) {
      f[x] = (sbox[x] >> outBit) & 1;
    }

    // Walsh-Hadamard transform
    const wht = walshHadamardTransform(f, n);
    let maxAbs = 0;
    for (let w = 0; w < size; w++) {
      const a = Math.abs(wht[w]);
      if (a > maxAbs) maxAbs = a;
    }

    const nl = (size / 2) - maxAbs / 2;
    if (nl < minNL) minNL = nl;
  }

  return minNL;
}

function walshHadamardTransform(f: Int32Array, n: number): Float64Array {
  const size = f.length;
  // Convert from {0,1} to {+1,-1}
  const s = new Float64Array(size);
  for (let i = 0; i < size; i++) {
    s[i] = 1 - 2 * f[i]; // 0->+1, 1->-1
  }

  // Fast WHT
  for (let i = 0; i < n; i++) {
    const step = 1 << i;
    for (let j = 0; j < size; j++) {
      if (!(j & step)) {
        const u = s[j];
        const v = s[j | step];
        s[j] = u + v;
        s[j | step] = u - v;
      }
    }
  }

  return s;
}

function testAlgebraicProperties(cipher: CipherUnderTest): TestResult {
  const key = randomBytes(cipher.keyBytes);
  let sboxes: number[][];
  try {
    sboxes = cipher.getSBoxes(key);
  } catch {
    return {
      name: 'S-Box Algebraic Properties',
      category: 'Algebraic',
      passed: false,
      score: 0,
      threshold: 0.50,
      details: 'SKIPPED: getSBoxes() not available.',
      severity: 'info',
    };
  }

  const results: string[] = [];
  let worstNL = Infinity;
  let worstDeg = Infinity;

  for (let si = 0; si < sboxes.length; si++) {
    const deg = computeAlgebraicDegree(sboxes[si]);
    const nl = computeNonlinearity(sboxes[si]);

    if (nl < worstNL) worstNL = nl;
    if (deg < worstDeg) worstDeg = deg;

    // Check for fixed points, inverse fixed points
    let fixedPts = 0;
    let zeroMap = sboxes[si][0];
    for (let x = 0; x < 256; x++) {
      if (sboxes[si][x] === x) fixedPts++;
    }

    results.push(
      `S${si}: degree=${deg}/7, NL=${nl}/112, ` +
      `fixed=${fixedPts}, S(0)=0x${zeroMap.toString(16)}`
    );
  }

  // AES S-box: degree=7, NL=112 (maximum possible for 8-bit).
  // Acceptable: degree>=6, NL>=100.
  const degPass = worstDeg >= 6;
  const nlPass = worstNL >= 100;
  const passed = degPass && nlPass;
  const score = Math.min(worstDeg / 7, worstNL / 112);

  return {
    name: 'S-Box Algebraic Properties',
    category: 'Algebraic',
    passed,
    score,
    threshold: 0.75,
    details: `Worst degree: ${worstDeg}/7 (${degPass ? 'OK' : 'LOW'}), ` +
             `Worst NL: ${worstNL}/112 (${nlPass ? 'OK' : 'LOW'}). ` +
             `AES: degree=7, NL=112. ` +
             results.join(' | '),
    severity: passed ? 'info' : 'critical',
  };
}

function testWalshSpectrum(cipher: CipherUnderTest): TestResult {
  // Full Walsh spectrum analysis — check distribution of Walsh coefficients.
  const key = randomBytes(cipher.keyBytes);
  let sboxes: number[][];
  try {
    sboxes = cipher.getSBoxes(key);
  } catch {
    return {
      name: 'Walsh Spectrum Analysis',
      category: 'Algebraic',
      passed: false,
      score: 0,
      threshold: 0.50,
      details: 'SKIPPED: getSBoxes() not available.',
      severity: 'info',
    };
  }

  const results: string[] = [];
  let worstFlatness = 0;

  for (let si = 0; si < sboxes.length; si++) {
    // Compute Walsh spectrum for each output bit component
    const spectrumDistribution = new Map<number, number>();

    for (let outBit = 0; outBit < 8; outBit++) {
      const f = new Int32Array(256);
      for (let x = 0; x < 256; x++) {
        f[x] = (sboxes[si][x] >> outBit) & 1;
      }
      const wht = walshHadamardTransform(f, 8);
      for (let w = 0; w < 256; w++) {
        const val = Math.abs(wht[w]);
        spectrumDistribution.set(val, (spectrumDistribution.get(val) || 0) + 1);
      }
    }

    // For a bent function (maximum NL), all Walsh coefficients have the same
    // absolute value. A good S-box should have a relatively flat spectrum.
    // Measure: how many distinct absolute values exist?
    const distinctValues = spectrumDistribution.size;
    // A perfectly flat spectrum: 1 distinct value. AES has ~5-10 distinct values.
    const flatness = distinctValues;
    if (flatness > worstFlatness) worstFlatness = flatness;

    results.push(`S${si}: ${distinctValues} distinct Walsh magnitudes`);
  }

  // More than 20 distinct magnitudes suggests poor algebraic structure
  const passed = worstFlatness <= 20;
  const score = Math.max(0, 1 - (worstFlatness - 5) / 30);

  return {
    name: 'Walsh Spectrum Analysis',
    category: 'Algebraic',
    passed,
    score,
    threshold: 0.50,
    details: `Worst spectrum flatness: ${worstFlatness} distinct magnitudes. ` +
             results.join(' | '),
    severity: passed ? 'info' : 'medium',
  };
}

// ---------------------------------------------------------------------------
// 6. KEY SCHEDULE ANALYSIS
// ---------------------------------------------------------------------------

function testKeyAvalanche(cipher: CipherUnderTest, samples: number = 200): TestResult {
  const blockBits = cipher.blockBytes * 8;
  const keyBits = cipher.keyBytes * 8;
  const idealFlips = blockBits / 2;
  let totalDeviation = 0;
  let worstDeviation = 0;

  for (let s = 0; s < samples; s++) {
    const key = randomBytes(cipher.keyBytes);
    const pt = randomBytes(cipher.blockBytes);
    const ct0 = cipher.encrypt(pt, key);

    // Flip each key bit
    for (let kb = 0; kb < Math.min(keyBits, 64); kb++) { // sample first 64 bits for speed
      const keyMod = flipBit(key, kb);
      const ct1 = cipher.encrypt(pt, keyMod);
      const hd = hammingDistance(ct0, ct1);
      const dev = Math.abs(hd - idealFlips) / idealFlips;
      totalDeviation += dev;
      if (dev > worstDeviation) worstDeviation = dev;
    }
  }

  const testedBits = Math.min(keyBits, 64);
  const avgDev = totalDeviation / (samples * testedBits);
  // NOTE: For 128-bit blocks, E[|Binom(128,0.5) - 64|/64] = sqrt(2/(pi*128)) ≈ 0.070.
  // Even truly random pairs average ~7% deviation. The worst over 12800 samples reaches ~35%.
  // Thresholds must account for this: avgDev < 0.10 (1.4x random baseline), worst < 0.50.
  const passed = avgDev < 0.10 && worstDeviation < 0.50;
  const score = Math.max(0, 1 - avgDev / 0.15);

  return {
    name: 'Key Avalanche Effect',
    category: 'Key Schedule',
    passed,
    score,
    threshold: 0.67,
    details: `Avg deviation from 50%: ${(avgDev * 100).toFixed(2)}%, ` +
             `Worst: ${(worstDeviation * 100).toFixed(2)}%. ` +
             `${samples} keys x ${testedBits} bit flips.`,
    severity: passed ? 'info' : 'critical',
  };
}

function testSubkeyIndependence(cipher: CipherUnderTest): TestResult {
  // Check correlation between round subkeys derived from same master key.
  // Good key schedule: subkeys should appear independent.
  //
  // STATISTICAL NOTE: Pearson correlation on n=16 bytes has stdev ~0.27.
  // The max over thousands of pairs will always be high for any cipher.
  // Instead, we POOL bytes across all master keys for each subkey-pair position
  // to get a reliable aggregate correlation with n = samples * bytesPerKey.
  const samples = 200;
  const findings: string[] = [];

  // First pass: determine the number of subkey pairs
  const probeKey = randomBytes(cipher.keyBytes);
  let probeSubkeys: Uint8Array[];
  try {
    probeSubkeys = cipher.deriveSubkeys(probeKey);
  } catch {
    return {
      name: 'Subkey Independence',
      category: 'Key Schedule',
      passed: false,
      score: 0,
      threshold: 0.50,
      details: 'SKIPPED: deriveSubkeys() not available.',
      severity: 'info',
    };
  }
  const numSubkeys = probeSubkeys.length;
  const bytesPerKey = probeSubkeys[0].length;
  const numPairs = numSubkeys - 1;

  // Accumulators for pooled Pearson: for each adjacent pair, pool all bytes across all keys
  const poolSumA = new Float64Array(numPairs);
  const poolSumB = new Float64Array(numPairs);
  const poolSumAB = new Float64Array(numPairs);
  const poolSumA2 = new Float64Array(numPairs);
  const poolSumB2 = new Float64Array(numPairs);
  const poolN = new Float64Array(numPairs);

  for (let s = 0; s < samples; s++) {
    const key = randomBytes(cipher.keyBytes);
    let subkeys: Uint8Array[];
    try {
      subkeys = cipher.deriveSubkeys(key);
    } catch {
      continue;
    }

    for (let r = 0; r < numPairs; r++) {
      const a = subkeys[r];
      const b = subkeys[r + 1];
      const minLen = Math.min(a.length, b.length);
      for (let i = 0; i < minLen; i++) {
        poolSumA[r] += a[i];
        poolSumB[r] += b[i];
        poolSumAB[r] += a[i] * b[i];
        poolSumA2[r] += a[i] * a[i];
        poolSumB2[r] += b[i] * b[i];
        poolN[r]++;
      }
    }
  }

  // Compute pooled Pearson correlation for each adjacent pair
  let maxCorr = 0;
  let avgCorr = 0;
  for (let r = 0; r < numPairs; r++) {
    const n = poolN[r];
    if (n < 2) continue;
    const num = n * poolSumAB[r] - poolSumA[r] * poolSumB[r];
    const den = Math.sqrt(
      (n * poolSumA2[r] - poolSumA[r] * poolSumA[r]) *
      (n * poolSumB2[r] - poolSumB[r] * poolSumB[r])
    );
    const corr = den === 0 ? 0 : Math.abs(num / den);
    avgCorr += corr;
    if (corr > maxCorr) maxCorr = corr;
  }
  avgCorr /= numPairs;

  // Also check: do different keys produce obviously related subkeys?
  const key1 = randomBytes(cipher.keyBytes);
  const key2 = flipBit(key1, 0);
  try {
    const sk1 = cipher.deriveSubkeys(key1);
    const sk2 = cipher.deriveSubkeys(key2);
    let identicalRounds = 0;
    for (let r = 0; r < sk1.length; r++) {
      if (r < sk2.length) {
        let same = true;
        for (let i = 0; i < sk1[r].length && i < sk2[r].length; i++) {
          if (sk1[r][i] !== sk2[r][i]) { same = false; break; }
        }
        if (same) identicalRounds++;
      }
    }
    if (identicalRounds > 0) {
      findings.push(`DANGER: ${identicalRounds} subkeys identical after 1-bit key change`);
    }
  } catch { /* skip */ }

  // With n=3200 per pair (200 keys * 16 bytes), 3-sigma threshold for random is ~0.053.
  // We use 0.15 as the threshold — generous enough for any reasonable key schedule.
  const passed = maxCorr < 0.15 && findings.length === 0;
  const score = Math.max(0, 1 - maxCorr / 0.30);

  return {
    name: 'Subkey Independence',
    category: 'Key Schedule',
    passed,
    score,
    threshold: 0.50,
    details: `Max pooled pairwise subkey correlation: ${maxCorr.toFixed(4)}, avg: ${avgCorr.toFixed(4)}. ` +
             `Pooled n=${Math.round(poolN[0])} per pair. ` +
             (findings.length > 0 ? findings.join(', ') : 'No structural weaknesses found.') +
             ` ${samples} master keys tested.`,
    severity: passed ? 'info' : 'high',
  };
}

function testRelatedKeyDifferentials(cipher: CipherUnderTest, samples: number = 500): TestResult {
  // Apply structured key differences and look for predictable output differences.
  const blockBytes = cipher.blockBytes;
  const keyBytes = cipher.keyBytes;
  const blockBits = blockBytes * 8;

  // Test strategies:
  // 1. Single-bit key differences with fixed plaintext
  // 2. Byte-level key differences
  // 3. Key complement (XOR with all-1s)

  const strategies: { name: string; keyDiff: (k: Uint8Array) => Uint8Array }[] = [
    { name: '1-bit', keyDiff: (k) => flipBit(k, 0) },
    { name: '1-byte', keyDiff: (k) => { const m = clone(k); m[0] ^= 0xff; return m; } },
    { name: 'complement', keyDiff: (k) => { const m = clone(k); for (let i = 0; i < m.length; i++) m[i] ^= 0xff; return m; } },
    { name: 'slide-1', keyDiff: (k) => { const m = new Uint8Array(k.length); for (let i = 0; i < k.length; i++) m[i] = k[(i + 1) % k.length]; return m; } },
  ];

  let worstBias = 0;
  const results: string[] = [];

  for (const strat of strategies) {
    // For each strategy, encrypt same plaintexts under K and K' and analyse output diff
    const diffCounts = new Map<string, number>();
    let totalHamming = 0;

    for (let s = 0; s < samples; s++) {
      const key = randomBytes(keyBytes);
      const keyMod = strat.keyDiff(key);
      const pt = randomBytes(blockBytes);

      const ct0 = cipher.encrypt(pt, key);
      const ct1 = cipher.encrypt(pt, keyMod);
      const diff = xorBlocks(ct0, ct1);

      totalHamming += hammingDistance(ct0, ct1);

      // Track most common output differences (byte 0 for simplicity)
      const diffByte = diff[0].toString();
      diffCounts.set(diffByte, (diffCounts.get(diffByte) || 0) + 1);
    }

    const avgHamming = totalHamming / samples;
    const idealHamming = blockBits / 2;
    const bias = Math.abs(avgHamming - idealHamming) / idealHamming;
    if (bias > worstBias) worstBias = bias;

    // Check if any single output difference dominates
    let maxFreq = 0;
    for (const [, count] of diffCounts) {
      if (count > maxFreq) maxFreq = count;
    }
    const maxDiffProb = maxFreq / samples;
    // For truly random, max freq of byte 0 should be ~samples/256
    const expectedMaxProb = 5 / 256; // generous upper bound

    results.push(
      `${strat.name}: avg_hd=${avgHamming.toFixed(1)}, ` +
      `bias=${(bias * 100).toFixed(1)}%, ` +
      `max_diff_freq=${maxDiffProb.toFixed(4)}`
    );

    if (maxDiffProb > expectedMaxProb) worstBias = Math.max(worstBias, maxDiffProb);
  }

  const passed = worstBias < 0.08;
  const score = Math.max(0, 1 - worstBias / 0.15);

  return {
    name: 'Related-Key Differential Analysis',
    category: 'Key Schedule',
    passed,
    score,
    threshold: 0.50,
    details: results.join(' || '),
    severity: passed ? 'info' : 'critical',
  };
}

// ---------------------------------------------------------------------------
// 7. SIDE-CHANNEL RESISTANCE
// ---------------------------------------------------------------------------

function testTimingVariation(cipher: CipherUnderTest, samples: number = 1000): TestResult {
  // Measure execution time variance across different inputs.
  // A constant-time cipher should have minimal variance.
  const key = randomBytes(cipher.keyBytes);

  const times: number[] = [];
  const specialInputs: { name: string; pt: Uint8Array }[] = [];

  // Generate special inputs that might trigger timing differences
  const allZero = new Uint8Array(cipher.blockBytes);
  const allOnes = new Uint8Array(cipher.blockBytes).fill(0xff);
  const sparse = new Uint8Array(cipher.blockBytes);
  sparse[0] = 1;

  specialInputs.push({ name: 'all-zero', pt: allZero });
  specialInputs.push({ name: 'all-ones', pt: allOnes });
  specialInputs.push({ name: 'sparse', pt: sparse });

  // Time random inputs
  for (let s = 0; s < samples; s++) {
    const pt = randomBytes(cipher.blockBytes);
    const start = performance.now();
    cipher.encrypt(pt, key);
    const end = performance.now();
    times.push(end - start);
  }

  // Time special inputs
  const specialTimes: { name: string; avg: number }[] = [];
  for (const { name, pt } of specialInputs) {
    const st: number[] = [];
    for (let i = 0; i < 100; i++) {
      const start = performance.now();
      cipher.encrypt(pt, key);
      const end = performance.now();
      st.push(end - start);
    }
    specialTimes.push({ name, avg: st.reduce((a, b) => a + b, 0) / st.length });
  }

  // Statistics on random inputs
  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  const variance = times.reduce((a, b) => a + (b - mean) ** 2, 0) / times.length;
  const stdDev = Math.sqrt(variance);
  const cv = mean > 0 ? stdDev / mean : 0; // coefficient of variation

  // Check if special inputs have significantly different timing
  let maxSpecialDeviation = 0;
  const specialDetails: string[] = [];
  for (const { name, avg } of specialTimes) {
    const deviation = mean > 0 ? Math.abs(avg - mean) / mean : 0;
    if (deviation > maxSpecialDeviation) maxSpecialDeviation = deviation;
    specialDetails.push(`${name}=${avg.toFixed(4)}ms (${(deviation * 100).toFixed(1)}% off)`);
  }

  // CV < 5% and no special input > 20% off mean = likely constant-time
  // Note: JS timing is noisy; be generous with thresholds.
  const passed = cv < 0.15 && maxSpecialDeviation < 0.30;
  const score = Math.max(0, 1 - Math.max(cv, maxSpecialDeviation) / 0.30);

  return {
    name: 'Timing Variation Analysis',
    category: 'Side-Channel',
    passed,
    score,
    threshold: 0.50,
    details: `Mean=${mean.toFixed(4)}ms, StdDev=${stdDev.toFixed(4)}ms, CV=${(cv * 100).toFixed(1)}%. ` +
             `Special inputs: ${specialDetails.join(', ')}. ` +
             `NOTE: JS timing resolution limits this test; native analysis recommended.`,
    severity: passed ? 'low' : 'high',
  };
}

function testKeyDependentBranches(cipher: CipherUnderTest): TestResult {
  // Heuristic: encrypt the same plaintext with many different keys and
  // measure timing. If timing correlates with key Hamming weight, there
  // are likely key-dependent branches.
  const pt = randomBytes(cipher.blockBytes);
  const samples = 500;

  const keyWeights: number[] = [];
  const encTimes: number[] = [];

  for (let s = 0; s < samples; s++) {
    const key = randomBytes(cipher.keyBytes);
    let hw = 0;
    for (let i = 0; i < key.length; i++) hw += popcount(key[i]);
    keyWeights.push(hw);

    const start = performance.now();
    // Multiple encryptions to reduce noise
    for (let i = 0; i < 50; i++) cipher.encrypt(pt, key);
    const end = performance.now();
    encTimes.push(end - start);
  }

  // Pearson correlation between key HW and timing
  const n = samples;
  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;
  for (let i = 0; i < n; i++) {
    sumX += keyWeights[i];
    sumY += encTimes[i];
    sumXY += keyWeights[i] * encTimes[i];
    sumX2 += keyWeights[i] * keyWeights[i];
    sumY2 += encTimes[i] * encTimes[i];
  }
  const num = n * sumXY - sumX * sumY;
  const den = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));
  const corr = den === 0 ? 0 : Math.abs(num / den);

  const passed = corr < 0.10;
  const score = Math.max(0, 1 - corr / 0.20);

  return {
    name: 'Key-Dependent Branch Detection',
    category: 'Side-Channel',
    passed,
    score,
    threshold: 0.50,
    details: `Correlation(key_HW, timing): ${corr.toFixed(6)}. ` +
             `Threshold: <0.10. ` +
             `${samples} keys, 50 encryptions each. ` +
             `For key-dependent S-boxes: check if S-box generation is constant-time.`,
    severity: passed ? 'info' : 'high',
  };
}

// ---------------------------------------------------------------------------
// 8. KNOWN-PLAINTEXT ATTACK SIMULATOR
// ---------------------------------------------------------------------------

function testKnownPlaintextDistinguisher(cipher: CipherUnderTest, pairs: number = 5000): TestResult {
  // Given N PT/CT pairs, can we distinguish VORTEX output from random?
  // A secure cipher should be indistinguishable from a random permutation.
  const key = randomBytes(cipher.keyBytes);

  // Collect real PT/CT pairs
  const realCTs = new Uint8Array(pairs * cipher.blockBytes);
  for (let i = 0; i < pairs; i++) {
    const pt = randomBytes(cipher.blockBytes);
    const ct = cipher.encrypt(pt, key);
    realCTs.set(ct, i * cipher.blockBytes);
  }

  // Generate "fake" random output for comparison
  const fakeCTs = randomBytes(pairs * cipher.blockBytes);

  // Test 1: Chi-squared on ciphertext bytes
  const realChi = chiSquaredBytes(realCTs);
  const fakeChi = chiSquaredBytes(fakeCTs);

  // Test 2: Serial correlation
  const realSC = Math.abs(serialCorrelation(realCTs));
  const fakeSC = Math.abs(serialCorrelation(fakeCTs));

  // Test 3: Check for repeated blocks (birthday paradox — shouldn't happen for 128-bit)
  const blockSet = new Set<string>();
  let realRepeats = 0;
  for (let i = 0; i < pairs; i++) {
    const block = Array.from(realCTs.slice(i * cipher.blockBytes, (i + 1) * cipher.blockBytes)).join(',');
    if (blockSet.has(block)) realRepeats++;
    blockSet.add(block);
  }

  // Test 4: Byte frequency per position
  let maxPositionalBias = 0;
  for (let pos = 0; pos < cipher.blockBytes; pos++) {
    const counts = new Array(256).fill(0);
    for (let i = 0; i < pairs; i++) {
      counts[realCTs[i * cipher.blockBytes + pos]]++;
    }
    const expected = pairs / 256;
    let positionChi2 = 0;
    for (let v = 0; v < 256; v++) {
      positionChi2 += (counts[v] - expected) ** 2 / expected;
    }
    // For 255 DOF, chi2 should be < ~310 at p=0.01
    if (positionChi2 > maxPositionalBias) maxPositionalBias = positionChi2;
  }

  // Test 5: Plaintext-ciphertext byte correlation
  let maxPCCorr = 0;
  for (let pos = 0; pos < cipher.blockBytes; pos++) {
    let sumA = 0, sumB = 0, sumAB = 0, sumA2 = 0, sumB2 = 0;
    for (let i = 0; i < Math.min(pairs, 2000); i++) {
      const pt = randomBytes(cipher.blockBytes);
      const ct = cipher.encrypt(pt, key);
      const a = pt[pos], b = ct[pos];
      sumA += a; sumB += b; sumAB += a * b; sumA2 += a * a; sumB2 += b * b;
    }
    const n = Math.min(pairs, 2000);
    const num2 = n * sumAB - sumA * sumB;
    const den2 = Math.sqrt((n * sumA2 - sumA * sumA) * (n * sumB2 - sumB * sumB));
    const corr = den2 === 0 ? 0 : Math.abs(num2 / den2);
    if (corr > maxPCCorr) maxPCCorr = corr;
  }

  const chiOk = realChi < 310;
  const scOk = realSC < 0.02;
  const repeatOk = realRepeats === 0;
  const posOk = maxPositionalBias < 310;
  const corrOk = maxPCCorr < 0.05;

  const passCount = [chiOk, scOk, repeatOk, posOk, corrOk].filter(Boolean).length;
  const passed = passCount >= 4;
  const score = passCount / 5;

  return {
    name: 'Known-Plaintext Distinguisher',
    category: 'Known-Plaintext',
    passed,
    score,
    threshold: 0.80,
    details: `Chi2=${realChi.toFixed(1)} (${chiOk ? 'OK' : 'FAIL'}), ` +
             `SerCorr=${realSC.toFixed(6)} (${scOk ? 'OK' : 'FAIL'}), ` +
             `Repeats=${realRepeats} (${repeatOk ? 'OK' : 'FAIL'}), ` +
             `MaxPosBias=${maxPositionalBias.toFixed(1)} (${posOk ? 'OK' : 'FAIL'}), ` +
             `MaxPT-CT_Corr=${maxPCCorr.toFixed(6)} (${corrOk ? 'OK' : 'FAIL'}). ` +
             `${pairs} pairs. FakeRef: chi2=${fakeChi.toFixed(1)}, sc=${fakeSC.toFixed(6)}.`,
    severity: passed ? 'info' : 'critical',
  };
}

function testKeyRecoverySimulation(cipher: CipherUnderTest): TestResult {
  // Attempt partial key recovery using statistical attacks.
  // If we can recover even one key byte with > chance probability, the cipher is broken.
  const key = randomBytes(cipher.keyBytes);
  const pairs = 10000;

  // Collect PT/CT pairs
  const data: { pt: Uint8Array; ct: Uint8Array }[] = [];
  for (let i = 0; i < pairs; i++) {
    const pt = randomBytes(cipher.blockBytes);
    data.push({ pt, ct: cipher.encrypt(pt, key) });
  }

  // Attack: for each candidate value of key byte 0, check if peeling off
  // a hypothetical last round S-box produces biased output.
  // This is a simplified 1R attack framework.
  let sboxes: number[][];
  try {
    sboxes = cipher.getSBoxes(key);
  } catch {
    return {
      name: 'Key Recovery Simulation (1R)',
      category: 'Known-Plaintext',
      passed: true,
      score: 0.5,
      threshold: 0.50,
      details: 'SKIPPED: requires getSBoxes() for 1R attack simulation.',
      severity: 'info',
    };
  }

  if (sboxes.length === 0) {
    return {
      name: 'Key Recovery Simulation (1R)',
      category: 'Known-Plaintext',
      passed: true,
      score: 0.5,
      threshold: 0.50,
      details: 'SKIPPED: no S-boxes available.',
      severity: 'info',
    };
  }

  // Build inverse S-box for attack
  const sbox = sboxes[0];
  const invSBox = new Array(256);
  for (let i = 0; i < 256; i++) invSBox[sbox[i]] = i;

  // For each candidate key byte, compute a distinguishing statistic
  const scores: number[] = [];
  for (let candidate = 0; candidate < 256; candidate++) {
    // Hypothesis: key byte 0 = candidate
    // Peel off: invSBox[ct[0] ^ candidate] should produce "intermediate" values
    // If correct key byte, intermediate has certain statistical property
    const intermediate = new Uint8Array(pairs);
    for (let i = 0; i < pairs; i++) {
      intermediate[i] = invSBox[data[i].ct[0] ^ candidate];
    }
    // Measure "structure" via chi-squared against uniform
    const chi2 = chiSquaredBytes(intermediate);
    scores.push(chi2);
  }

  // The correct key byte should NOT produce a significantly different chi2
  // than wrong guesses (if the cipher is secure).
  const correctScore = scores[key[0]];
  const sortedScores = [...scores].sort((a, b) => a - b);
  const rank = sortedScores.indexOf(correctScore);
  // If correct key ranks in top 3 most or least structured, that's suspicious
  const suspicious = rank < 3 || rank > 252;

  // Also check: is the variance of scores across candidates low?
  // (All should look equally random if cipher is secure)
  const meanScore = scores.reduce((a, b) => a + b, 0) / 256;
  const variance = scores.reduce((a, b) => a + (b - meanScore) ** 2, 0) / 256;
  const cv = Math.sqrt(variance) / meanScore;

  const passed = !suspicious && cv < 0.30;
  const score2 = passed ? 1.0 : Math.max(0, 1 - (suspicious ? 0.5 : 0) - cv);

  return {
    name: 'Key Recovery Simulation (1R Attack)',
    category: 'Known-Plaintext',
    passed,
    score: score2,
    threshold: 0.50,
    details: `Correct key byte rank: ${rank}/256 (${suspicious ? 'SUSPICIOUS' : 'OK'}). ` +
             `Score CV across candidates: ${(cv * 100).toFixed(1)}% (${cv < 0.30 ? 'OK' : 'HIGH'}). ` +
             `${pairs} PT/CT pairs. Attack: 1-round peel with known S-box.`,
    severity: passed ? 'info' : 'critical',
  };
}

// ---------------------------------------------------------------------------
// 9. CONSISTENCY & CORRECTNESS
// ---------------------------------------------------------------------------

function testEncryptDecryptConsistency(cipher: CipherUnderTest, samples: number = 500): TestResult {
  let failures = 0;
  const failDetails: string[] = [];

  for (let s = 0; s < samples; s++) {
    const key = randomBytes(cipher.keyBytes);
    const pt = randomBytes(cipher.blockBytes);
    const ct = cipher.encrypt(pt, key);
    const ptRecovered = cipher.decrypt(ct, key);

    if (pt.length !== ptRecovered.length) {
      failures++;
      if (failDetails.length < 3) failDetails.push(`Sample ${s}: length mismatch`);
      continue;
    }

    let match = true;
    for (let i = 0; i < pt.length; i++) {
      if (pt[i] !== ptRecovered[i]) { match = false; break; }
    }
    if (!match) {
      failures++;
      if (failDetails.length < 3) {
        failDetails.push(
          `Sample ${s}: pt[0..3]=${Array.from(pt.slice(0, 4)).map(b => b.toString(16)).join(' ')}, ` +
          `recovered[0..3]=${Array.from(ptRecovered.slice(0, 4)).map(b => b.toString(16)).join(' ')}`
        );
      }
    }
  }

  const passed = failures === 0;
  const score = 1 - failures / samples;

  return {
    name: 'Encrypt/Decrypt Consistency',
    category: 'Correctness',
    passed,
    score,
    threshold: 1.0,
    details: passed
      ? `All ${samples} round-trips passed.`
      : `${failures}/${samples} failures. ${failDetails.join(' | ')}`,
    severity: passed ? 'info' : 'critical',
  };
}

function testPermutationProperty(cipher: CipherUnderTest): TestResult {
  // For a block cipher with fixed key, the encryption function should be a
  // bijection (permutation). Test: no two distinct plaintexts should produce
  // the same ciphertext.
  const key = randomBytes(cipher.keyBytes);
  const samples = 5000;
  const seen = new Set<string>();
  let collisions = 0;

  for (let i = 0; i < samples; i++) {
    const pt = randomBytes(cipher.blockBytes);
    const ct = cipher.encrypt(pt, key);
    const ctHex = Array.from(ct).map(b => b.toString(16).padStart(2, '0')).join('');
    if (seen.has(ctHex)) {
      collisions++;
    }
    seen.add(ctHex);
  }

  // With 128-bit blocks and 5000 samples, birthday collision probability is negligible
  const passed = collisions === 0;

  return {
    name: 'Permutation Property (No Collisions)',
    category: 'Correctness',
    passed,
    score: passed ? 1 : 0,
    threshold: 1.0,
    details: passed
      ? `No collisions in ${samples} encryptions.`
      : `CRITICAL: ${collisions} collisions found in ${samples} encryptions!`,
    severity: passed ? 'info' : 'critical',
  };
}

// ---------------------------------------------------------------------------
// 10. FULL ATTACK SUITE RUNNER
// ---------------------------------------------------------------------------

export async function runFullAttackSuite(cipher: CipherUnderTest): Promise<{
  results: TestResult[];
  summary: string;
  verdict: 'SECURE' | 'WEAK' | 'BROKEN';
}> {
  console.log(`\n${'='.repeat(72)}`);
  console.log(`  VORTEX ATTACK SUITE — Targeting: ${cipher.name}`);
  console.log(`  Block: ${cipher.blockBytes * 8}-bit, Key: ${cipher.keyBytes * 8}-bit, Rounds: ${cipher.rounds}`);
  console.log(`${'='.repeat(72)}\n`);

  const startTime = performance.now();
  const results: TestResult[] = [];

  const tests: (() => TestResult)[] = [
    // Correctness (run first — if these fail, nothing else matters)
    () => testEncryptDecryptConsistency(cipher),
    () => testPermutationProperty(cipher),

    // Statistical
    () => testAvalancheEffect(cipher),
    () => testSAC(cipher),
    () => testBIC(cipher),
    () => testOutputRandomness(cipher),

    // Differential
    () => testDifferentialSBoxes(cipher),
    () => testDifferentialPropagation(cipher),
    () => testImpossibleDifferentials(cipher),

    // Linear
    () => testLinearSBoxes(cipher),
    () => testLinearBiasAccumulation(cipher),

    // Algebraic
    () => testAlgebraicProperties(cipher),
    () => testWalshSpectrum(cipher),

    // Key Schedule
    () => testKeyAvalanche(cipher),
    () => testSubkeyIndependence(cipher),
    () => testRelatedKeyDifferentials(cipher),

    // Side-Channel
    () => testTimingVariation(cipher),
    () => testKeyDependentBranches(cipher),

    // Known-Plaintext
    () => testKnownPlaintextDistinguisher(cipher),
    () => testKeyRecoverySimulation(cipher),
  ];

  for (const test of tests) {
    try {
      const result = test();
      results.push(result);
      printResult(result);
    } catch (err) {
      const errResult: TestResult = {
        name: test.name || 'Unknown Test',
        category: 'Error',
        passed: false,
        score: 0,
        threshold: 0,
        details: `EXCEPTION: ${err instanceof Error ? err.message : String(err)}`,
        severity: 'high',
      };
      results.push(errResult);
      printResult(errResult);
    }
  }

  const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);

  // Tally
  const total = results.length;
  const passed = results.filter(r => r.passed).length;
  const failed = total - passed;
  const criticals = results.filter(r => !r.passed && r.severity === 'critical').length;
  const highs = results.filter(r => !r.passed && r.severity === 'high').length;
  const avgScore = results.reduce((a, r) => a + r.score, 0) / total;

  let verdict: 'SECURE' | 'WEAK' | 'BROKEN';
  if (criticals > 0 || failed > total * 0.3) {
    verdict = 'BROKEN';
  } else if (highs > 0 || failed > 0) {
    verdict = 'WEAK';
  } else {
    verdict = 'SECURE';
  }

  const summary = [
    '',
    '='.repeat(72),
    `  VERDICT: ${verdict}`,
    '='.repeat(72),
    `  Tests: ${passed}/${total} passed, ${failed} failed`,
    `  Critical failures: ${criticals}`,
    `  High failures: ${highs}`,
    `  Average score: ${(avgScore * 100).toFixed(1)}%`,
    `  Elapsed: ${elapsed}s`,
    '',
    verdict === 'BROKEN'
      ? '  This cipher has CRITICAL weaknesses. Do NOT use in production.'
      : verdict === 'WEAK'
      ? '  This cipher has weaknesses that may be exploitable. Needs hardening.'
      : '  No weaknesses detected by this suite. Further analysis recommended.',
    '='.repeat(72),
    '',
  ].join('\n');

  console.log(summary);
  return { results, summary, verdict };
}

function printResult(r: TestResult): void {
  const status = r.passed ? 'PASS' : 'FAIL';
  const icon = r.passed ? '[+]' : '[-]';
  const sevTag = r.passed ? '' : ` [${r.severity.toUpperCase()}]`;
  console.log(`${icon} ${status} ${r.category} / ${r.name} — score: ${(r.score * 100).toFixed(0)}%${sevTag}`);
  console.log(`    ${r.details}`);
  console.log('');
}

// ---------------------------------------------------------------------------
// 11. STANDALONE ANALYSIS TOOLS (can be used independently)
// ---------------------------------------------------------------------------

/**
 * Analyse a single S-box in isolation. Useful during S-box design.
 */
export function analyseSBox(sbox: number[]): {
  differentialUniformity: number;
  maxLinearBias: number;
  algebraicDegree: number;
  nonlinearity: number;
  fixedPoints: number;
  hasSboxOf0Equals0: boolean;
} {
  const ddt = buildDifferentialDistributionTable(sbox);
  const lat = buildLinearApproximationTable(sbox);
  const size = sbox.length;
  const half = size / 2;

  let maxDU = 0;
  for (let dx = 1; dx < size; dx++) {
    for (let dy = 0; dy < size; dy++) {
      if (ddt[dx][dy] > maxDU) maxDU = ddt[dx][dy];
    }
  }

  let maxBias = 0;
  for (let im = 1; im < size; im++) {
    for (let om = 1; om < size; om++) {
      const bias = Math.abs(lat[im][om] - half) / size;
      if (bias > maxBias) maxBias = bias;
    }
  }

  let fixedPoints = 0;
  for (let x = 0; x < size; x++) if (sbox[x] === x) fixedPoints++;

  return {
    differentialUniformity: maxDU,
    maxLinearBias: maxBias,
    algebraicDegree: computeAlgebraicDegree(sbox),
    nonlinearity: computeNonlinearity(sbox),
    fixedPoints,
    hasSboxOf0Equals0: sbox[0] === 0,
  };
}

/**
 * Generate the full DDT and LAT for an S-box. For deep manual analysis.
 */
export function getSBoxTables(sbox: number[]): {
  ddt: number[][];
  lat: number[][];
} {
  return {
    ddt: buildDifferentialDistributionTable(sbox),
    lat: buildLinearApproximationTable(sbox),
  };
}

/**
 * Quick health-check: run only the fastest tests.
 */
export async function quickCheck(cipher: CipherUnderTest): Promise<{
  passed: boolean;
  failures: string[];
}> {
  const failures: string[] = [];

  const consistency = testEncryptDecryptConsistency(cipher, 100);
  if (!consistency.passed) failures.push(consistency.details);

  const permutation = testPermutationProperty(cipher);
  if (!permutation.passed) failures.push(permutation.details);

  const avalanche = testAvalancheEffect(cipher, 50);
  if (!avalanche.passed) failures.push(`Avalanche: ${avalanche.details}`);

  const randomness = testOutputRandomness(cipher, 500);
  if (!randomness.passed) failures.push(`Randomness: ${randomness.details}`);

  return { passed: failures.length === 0, failures };
}

// ---------------------------------------------------------------------------
// 12. EXPORTS
// ---------------------------------------------------------------------------

export {
  // Low-level building blocks
  buildDifferentialDistributionTable,
  buildLinearApproximationTable,
  computeAlgebraicDegree,
  computeNonlinearity,
  testAlgebraicProperties,
  // Individual tests for targeted analysis
  testAvalancheEffect,
  testBIC,
  testDifferentialPropagation,
  testDifferentialSBoxes,
  testEncryptDecryptConsistency,
  testImpossibleDifferentials,
  testKeyAvalanche,
  testKeyDependentBranches,
  testKeyRecoverySimulation,
  testKnownPlaintextDistinguisher,
  testLinearBiasAccumulation,
  testLinearSBoxes,
  testOutputRandomness,
  testPermutationProperty,
  testRelatedKeyDifferentials,
  testSAC,
  testSubkeyIndependence,
  testTimingVariation,
  testWalshSpectrum,
  walshHadamardTransform,
};
