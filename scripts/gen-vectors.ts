// Writes cross-language test vectors to vectors/vectors.json.
// The Rust crate's tests/vectors.rs checks its output against this file.
import { mkdirSync, writeFileSync } from "node:fs";
import { aeadEncrypt, encryptBlock, expandKey } from "../src/vortex-cipher";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const seq = (n: number, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

const cases = [
  { key: new Uint8Array(32), pt: new Uint8Array(16) },
  { key: seq(32), pt: seq(16) },
  { key: seq(32, 0xa0), pt: seq(16, 0x55) },
];
const block = cases.map(({ key, pt }) => ({ key: hex(key), plaintext: hex(pt), ciphertext: hex(encryptBlock(pt, expandKey(key))) }));

const aead = [
  { key: seq(32), nonce: seq(12, 0x10), aad: new Uint8Array(0), pt: new Uint8Array(0) },
  { key: seq(32), nonce: seq(12, 0x10), aad: new TextEncoder().encode("header"), pt: new TextEncoder().encode("VORTEX-256 test vector") },
  { key: seq(32, 0x40), nonce: seq(12), aad: seq(7, 3), pt: seq(67, 9) },
].map(({ key, nonce, aad, pt }) => {
  const { ciphertext, tag } = aeadEncrypt(key, nonce, pt, aad);
  return { key: hex(key), nonce: hex(nonce), aad: hex(aad), plaintext: hex(pt), ciphertext: hex(ciphertext), tag: hex(tag) };
});

mkdirSync("vectors", { recursive: true });
writeFileSync("vectors/vectors.json", JSON.stringify({ block, aead }, null, 2) + "\n");
console.log(`wrote ${block.length} block and ${aead.length} AEAD vectors`);
