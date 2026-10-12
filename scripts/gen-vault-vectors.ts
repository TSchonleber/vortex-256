// Writes VORTEX-PQ vault known-answer vectors to vectors/vortex-pq-vault.json (cheap Argon2 params).
import { writeFileSync } from "node:fs";
import { vaultSeal } from "../src/pq/vault";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const enc = (s: string) => new TextEncoder().encode(s);
const seq = (n: number, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

const cases = [
  { password: enc("password"), plaintext: new Uint8Array(0), aad: new Uint8Array(0), salt: new Uint8Array(32).fill(7), params: { m: 64, t: 1, p: 1 } },
  { password: enc("correct horse battery staple"), plaintext: enc("abandon ability able about above absent"), aad: enc("wallet:main"), salt: seq(32), params: { m: 256, t: 2, p: 2 } },
];

const vectors = [];
for (const c of cases) {
  const vault = await vaultSeal(c.password, c.plaintext, c.aad, { params: c.params, salt: c.salt, insecureAllowWeakParams: true });
  vectors.push({ password: hex(c.password), plaintext: hex(c.plaintext), aad: hex(c.aad), salt: hex(c.salt), params: c.params, vault: hex(vault) });
}
writeFileSync("vectors/vortex-pq-vault.json", JSON.stringify({ spec: "VORTEX-PQ vault v1 (docs/SPEC.md)", vectors }, null, 2) + "\n");
console.log(`wrote ${vectors.length} vault vectors`);
