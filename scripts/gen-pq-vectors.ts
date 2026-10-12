// Writes VORTEX-PQ known-answer vectors to vectors/vortex-pq.json.
// rust/tests/pq_vectors.rs checks the Rust implementation against this file.
// Regenerate only when the spec version changes; the TS test suite pins these values.
import { writeFileSync } from "node:fs";
import { publicKeyFromSeed, seal } from "../src/pq/envelope";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const seq = (n: number, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const enc = (s: string) => new TextEncoder().encode(s);

const cases = [
  { seed: new Uint8Array(32).fill(0x01), eseed: new Uint8Array(64).fill(0x02), plaintext: new Uint8Array(0), aad: new Uint8Array(0) },
  { seed: seq(32), eseed: seq(64, 0x80), plaintext: enc("VORTEX-PQ v1 test vector"), aad: enc("header") },
  { seed: seq(32, 0x40), eseed: seq(64, 3), plaintext: seq(1000, 9), aad: seq(33, 5) },
];

const vectors = cases.map((c) => {
  const publicKey = publicKeyFromSeed(c.seed);
  return {
    seed: hex(c.seed),
    public_key: hex(publicKey),
    eseed: hex(c.eseed),
    plaintext: hex(c.plaintext),
    aad: hex(c.aad),
    envelope: hex(seal(publicKey, c.plaintext, c.aad, c.eseed)),
  };
});

writeFileSync("vectors/vortex-pq.json", JSON.stringify({ spec: "VORTEX-PQ v1 (docs/SPEC.md)", vectors }, null, 2) + "\n");
console.log(`wrote ${vectors.length} VORTEX-PQ vectors`);
