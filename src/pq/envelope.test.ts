import { readFileSync } from "node:fs";
import {
  decapsulate,
  encapsulate,
  generateKeyPair,
  KEM_CIPHERTEXT_SIZE,
  open,
  OpenError,
  OVERHEAD,
  PUBLIC_KEY_SIZE,
  publicKeyFromSeed,
  seal,
} from "./envelope";

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const seq = (n: number, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

describe("VORTEX-PQ key generation", () => {
  it("derives a 1600-byte public key deterministically from the seed", () => {
    const pk1 = publicKeyFromSeed(seq(32));
    expect(pk1.length).toBe(PUBLIC_KEY_SIZE);
    expect(hex(publicKeyFromSeed(seq(32)))).toBe(hex(pk1));
    expect(hex(publicKeyFromSeed(seq(32, 1)))).not.toBe(hex(pk1));
  });

  it("rejects seeds of the wrong length", () => {
    expect(() => publicKeyFromSeed(new Uint8Array(31))).toThrow();
  });
});

describe("VORTEX-PQ hybrid KEM", () => {
  it("encapsulation and decapsulation agree", () => {
    const { secretKey, publicKey } = generateKeyPair();
    const { ciphertext, sharedSecret } = encapsulate(publicKey);
    expect(ciphertext.length).toBe(KEM_CIPHERTEXT_SIZE);
    expect(sharedSecret.length).toBe(64);
    expect(hex(decapsulate(secretKey, ciphertext))).toBe(hex(sharedSecret));
  });

  it("a different recipient derives a different secret", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    const { ciphertext, sharedSecret } = encapsulate(a.publicKey);
    expect(hex(decapsulate(b.secretKey, ciphertext))).not.toBe(hex(sharedSecret));
  });

  it("tampering with either KEM component changes the secret", () => {
    const { secretKey, publicKey } = generateKeyPair();
    const { ciphertext, sharedSecret } = encapsulate(publicKey);
    for (const i of [0, 1000, KEM_CIPHERTEXT_SIZE - 33]) {
      const t = ciphertext.slice();
      t[i] ^= 1;
      expect(hex(decapsulate(secretKey, t))).not.toBe(hex(sharedSecret));
    }
    const t = ciphertext.slice();
    t[KEM_CIPHERTEXT_SIZE - 1] ^= 0x40; // X25519 share
    let changed = true;
    try { changed = hex(decapsulate(secretKey, t)) !== hex(sharedSecret); } catch { /* low-order point rejected */ }
    expect(changed).toBe(true);
  });

  it("rejects a low-order X25519 share", () => {
    const { secretKey, publicKey } = generateKeyPair();
    const { ciphertext } = encapsulate(publicKey);
    const t = ciphertext.slice();
    t.fill(0, KEM_CIPHERTEXT_SIZE - 32);
    expect(() => decapsulate(secretKey, t)).toThrow();
  });
});

describe("VORTEX-PQ envelope", () => {
  const { secretKey, publicKey } = generateKeyPair();

  it("round-trips messages of many lengths", () => {
    for (const n of [0, 1, 15, 16, 17, 31, 32, 33, 255, 4096, 100_000]) {
      const pt = seq(n, n);
      const env = seal(publicKey, pt);
      expect(env.length).toBe(n + OVERHEAD);
      expect(hex(open(secretKey, env))).toBe(hex(pt));
    }
  });

  it("authenticates associated data", () => {
    const env = seal(publicKey, enc("seed phrase backup"), enc("wallet:1"));
    expect(new TextDecoder().decode(open(secretKey, env, enc("wallet:1")))).toBe("seed phrase backup");
    expect(() => open(secretKey, env, enc("wallet:2"))).toThrow(OpenError);
    expect(() => open(secretKey, env)).toThrow(OpenError);
  });

  it("produces a different envelope every time", () => {
    const pt = enc("same message");
    expect(hex(seal(publicKey, pt))).not.toBe(hex(seal(publicKey, pt)));
  });

  it("rejects a flipped bit anywhere in the envelope", () => {
    const env = seal(publicKey, seq(100));
    const positions = [0, 3, 4, 5, 6, 800, 1574, 1605, 1606, 1620, 1637, 1638, 1700, env.length - 17, env.length - 1];
    for (const i of positions) {
      const t = env.slice();
      t[i] ^= 0x01;
      expect(() => open(secretKey, t), `byte ${i}`).toThrow(OpenError);
    }
  });

  it("rejects truncated and extended envelopes", () => {
    const env = seal(publicKey, seq(40));
    expect(() => open(secretKey, env.subarray(0, env.length - 1))).toThrow(OpenError);
    expect(() => open(secretKey, env.subarray(0, 100))).toThrow(OpenError);
    const longer = new Uint8Array(env.length + 1);
    longer.set(env);
    expect(() => open(secretKey, longer)).toThrow(OpenError);
  });

  it("rejects the wrong recipient", () => {
    const other = generateKeyPair();
    expect(() => open(other.secretKey, seal(publicKey, enc("x")))).toThrow(OpenError);
  });

  it("is deterministic given eseed (test-vector mode)", () => {
    const e = seq(64, 7);
    expect(hex(seal(publicKey, enc("v"), new Uint8Array(0), e))).toBe(hex(seal(publicKey, enc("v"), new Uint8Array(0), e)));
  });
});

describe("VORTEX-PQ known-answer vectors", () => {
  const file = JSON.parse(readFileSync(new URL("../../vectors/vortex-pq.json", import.meta.url), "utf8"));
  it("matches every stored vector", () => {
    expect(file.vectors.length).toBeGreaterThan(0);
    for (const v of file.vectors) {
      const seed = unhex(v.seed);
      expect(hex(publicKeyFromSeed(seed))).toBe(v.public_key);
      const env = seal(unhex(v.public_key), unhex(v.plaintext), unhex(v.aad), unhex(v.eseed));
      expect(hex(env)).toBe(v.envelope);
      expect(hex(open(seed, env, unhex(v.aad)))).toBe(v.plaintext);
    }
  });
});
