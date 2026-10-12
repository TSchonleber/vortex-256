/**
 * HSS/LMS tests: RFC 8554 Appendix F + RFC 9858 Appendix A vectors (extracted
 * programmatically from the RFC .txt files into vectors/*.json), keygen-from-seed
 * reproduction, round trips for every parameter set, tamper, state and exhaustion.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  LMOTS,
  LMS,
  decodeHssPublicKey,
  decodeHssSignature,
  deserializeHssPrivateKey,
  deserializeLmsPrivateKey,
  encodeHssPublicKey,
  encodeHssSignature,
  hssFromLmsKeys,
  hssKeyGen,
  hssPublicKey,
  hssSign,
  hssVerify,
  lmotsParams,
  lmsDeriveChildKey,
  lmsKeyGen,
  lmsParams,
  lmsPrivateKeyFromSeed,
  lmsRemaining,
  lmsSign,
  lmsVerify,
  serializeHssPrivateKey,
  serializeLmsPrivateKey,
  type HssPrivateKey,
  type LmsPrivateKey,
} from "./lms";

interface VectorCase {
  name: string;
  seed: string;
  i: string;
  seed2?: string;
  i2?: string;
  levels?: string;
  index?: string;
  publicKey: string;
  message: string;
  signature: string;
}

const loadCases = (file: string): VectorCase[] =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../vectors/${file}`, import.meta.url)), "utf8")).cases;

const hex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const enc = (s: string) => new TextEncoder().encode(s);
const seq = (start: number, len: number) => Uint8Array.from({ length: len }, (_, i) => (start + i) & 0xff);
const u32 = (b: Uint8Array, off: number) => ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;

const RFC8554 = loadCases("rfc8554.json");
const RFC9858 = loadCases("rfc9858.json");
const CROSS = loadCases("lms-cross.json");

// ----------------------------------------------------------------------------

describe("parameter sets", () => {
  it("typecodes match RFC 8554 Tables 1-2 and RFC 9858 Tables 1-2", () => {
    const ots: Record<string, number> = {
      LMOTS_SHA256_N32_W1: 1, LMOTS_SHA256_N32_W2: 2, LMOTS_SHA256_N32_W4: 3, LMOTS_SHA256_N32_W8: 4,
      LMOTS_SHA256_N24_W1: 5, LMOTS_SHA256_N24_W2: 6, LMOTS_SHA256_N24_W4: 7, LMOTS_SHA256_N24_W8: 8,
      LMOTS_SHAKE_N32_W1: 9, LMOTS_SHAKE_N32_W2: 10, LMOTS_SHAKE_N32_W4: 11, LMOTS_SHAKE_N32_W8: 12,
      LMOTS_SHAKE_N24_W1: 13, LMOTS_SHAKE_N24_W2: 14, LMOTS_SHAKE_N24_W4: 15, LMOTS_SHAKE_N24_W8: 16,
    };
    const lms: Record<string, number> = {
      LMS_SHA256_M32_H5: 5, LMS_SHA256_M32_H10: 6, LMS_SHA256_M32_H15: 7, LMS_SHA256_M32_H20: 8, LMS_SHA256_M32_H25: 9,
      LMS_SHA256_M24_H5: 10, LMS_SHA256_M24_H10: 11, LMS_SHA256_M24_H15: 12, LMS_SHA256_M24_H20: 13, LMS_SHA256_M24_H25: 14,
      LMS_SHAKE_M32_H5: 15, LMS_SHAKE_M32_H10: 16, LMS_SHAKE_M32_H15: 17, LMS_SHAKE_M32_H20: 18, LMS_SHAKE_M32_H25: 19,
      LMS_SHAKE_M24_H5: 20, LMS_SHAKE_M24_H10: 21, LMS_SHAKE_M24_H15: 22, LMS_SHAKE_M24_H20: 23, LMS_SHAKE_M24_H25: 24,
    };
    expect(Object.fromEntries(Object.values(LMOTS).map((p) => [p.name, p.type]))).toEqual(ots);
    expect(Object.fromEntries(Object.values(LMS).map((p) => [p.name, p.type]))).toEqual(lms);
    expect(() => lmotsParams(0)).toThrow();
    expect(() => lmotsParams(17)).toThrow();
    expect(() => lmsParams(4)).toThrow();
    expect(() => lmsParams(25)).toThrow();
  });

  it("p and ls match the RFC 8554 Appendix B formulas", () => {
    for (const ots of Object.values(LMOTS)) {
      const u = Math.ceil((8 * ots.n) / ots.w);
      const v = Math.ceil((Math.floor(Math.log2(((1 << ots.w) - 1) * u)) + 1) / ots.w);
      expect(ots.p).toBe(u + v);
      expect(ots.ls).toBe(16 - v * ots.w);
    }
  });
});

describe("RFC test vectors", () => {
  it("extracted all cases", () => {
    expect(RFC8554).toHaveLength(2);
    expect(RFC9858).toHaveLength(4);
  });

  for (const c of [...RFC8554, ...RFC9858]) {
    it(`${c.name}: verifies`, () => {
      expect(hssVerify(hex(c.publicKey), hex(c.message), hex(c.signature))).toBe(true);
    });

    it(`${c.name}: wire format round-trips`, () => {
      expect(toHex(encodeHssPublicKey(decodeHssPublicKey(hex(c.publicKey))))).toBe(c.publicKey);
      expect(toHex(encodeHssSignature(decodeHssSignature(hex(c.signature))))).toBe(c.signature);
    });

    it(`${c.name}: rejects a modified message`, () => {
      const msg = hex(c.message);
      msg[0] ^= 1;
      expect(hssVerify(hex(c.publicKey), msg, hex(c.signature))).toBe(false);
    });
  }

  // A.4 is an H20 tree (2^20 leaves): verify-only, keygen is out of reach here.
  for (const c of RFC9858.filter((c) => decodeHssPublicKey(hex(c.publicKey)).top.lms.h <= 10)) {
    it(`${c.name}: keygen from SEED reproduces the public key and signature`, () => {
      const pub = decodeHssPublicKey(hex(c.publicKey));
      const q = decodeHssSignature(hex(c.signature)).sig.q;
      const key = lmsPrivateKeyFromSeed(pub.top.lms, pub.top.ots, hex(c.seed), hex(c.i), q);
      const hss = hssFromLmsKeys([key]);
      expect(toHex(hssPublicKey(hss))).toBe(c.publicKey);
      expect(toHex(hssSign(hss, hex(c.message)).signature)).toBe(c.signature);
    });
  }

  it("RFC 8554 Test Case 2: second-level SEED/I derive from the top tree, signature reproduces", () => {
    const c = RFC8554[1];
    const pub = decodeHssPublicKey(hex(c.publicKey));
    const sig = decodeHssSignature(hex(c.signature));
    const childPub = sig.signedPublicKeys[0].pub;
    const top = lmsPrivateKeyFromSeed(pub.top.lms, pub.top.ots, hex(c.seed), hex(c.i), sig.signedPublicKeys[0].sig.q);
    const child = lmsDeriveChildKey(top, childPub.lms, childPub.ots);
    expect(toHex(child.seed)).toBe(c.seed2);
    expect(toHex(child.I)).toBe(c.i2);
    // The vector's child had already made sig.sig.q signatures.
    const childAtQ = lmsPrivateKeyFromSeed(childPub.lms, childPub.ots, child.seed, child.I, sig.sig.q);
    const hss = hssFromLmsKeys([top, childAtQ]);
    expect(toHex(hssPublicKey(hss))).toBe(c.publicKey);
    expect(toHex(hssSign(hss, hex(c.message)).signature)).toBe(c.signature);
  });
});

describe("cross-language vectors (vectors/lms-cross.json)", () => {
  for (const c of CROSS) {
    it(`${c.name}: reproduces`, () => {
      const levels = c.levels!.split(",").map((l) => {
        const [lms, ots] = l.split("/").map(Number);
        return { lms, ots };
      });
      let { publicKey, privateKey } = hssKeyGen(levels, hex(c.seed), hex(c.i));
      expect(toHex(publicKey)).toBe(c.publicKey);
      for (let k = 0; k < Number(c.index); k++) privateKey = hssSign(privateKey, enc("filler")).nextKey;
      const { signature } = hssSign(privateKey, hex(c.message));
      expect(toHex(signature)).toBe(c.signature);
      expect(hssVerify(publicKey, hex(c.message), signature)).toBe(true);
    });
  }
});

describe("round trips", () => {
  // Every LM-OTS set with the H5 LMS set of the same hash family and width.
  for (const ots of Object.values(LMOTS)) {
    const family = ots.name.replace("LMOTS_", "LMS_").replace(/_N(\d+)_W\d+$/, "_M$1_H5");
    it(`${family} / ${ots.name}`, () => {
      const lms = LMS[family];
      const { publicKey, privateKey } = lmsKeyGen(lms, ots, seq(0x11, lms.m), seq(0x77, 16));
      const msg = enc(`round trip ${ots.name}`);
      const { signature, nextKey } = lmsSign(privateKey, msg);
      expect(signature.length).toBe(4 + 4 + ots.n + ots.p * ots.n + 4 + lms.h * lms.m);
      expect(lmsVerify(publicKey, msg, signature)).toBe(true);
      expect(nextKey.q).toBe(1);
      const second = lmsSign(nextKey, msg);
      expect(lmsVerify(publicKey, msg, second.signature)).toBe(true);
      expect(toHex(second.signature)).not.toBe(toHex(signature));
    });
  }

  it("every LMS height parses (H5..H25) via signature length checks", () => {
    for (const lms of Object.values(LMS)) expect(lmsParams(lms.type)).toBe(lms);
  });

  it("H10 tree signs and verifies at several leaves", () => {
    const { publicKey, privateKey } = lmsKeyGen("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W1", seq(1, 24), seq(2, 16));
    let key: LmsPrivateKey = privateKey;
    for (let k = 0; k < 40; k++) {
      const msg = enc(`m${k}`);
      const r = lmsSign(key, msg);
      if (k % 13 === 0) expect(lmsVerify(publicKey, msg, r.signature)).toBe(true);
      key = r.nextKey;
    }
    expect(lmsRemaining(key)).toBe(1024 - 40);
  });

  it("HSS L=3 across tree boundaries", () => {
    const levels = [
      { lms: "LMS_SHA256_M24_H5", ots: "LMOTS_SHA256_N24_W2" },
      { lms: "LMS_SHAKE_M32_H5", ots: "LMOTS_SHAKE_N32_W1" },
      { lms: "LMS_SHA256_M32_H5", ots: "LMOTS_SHA256_N32_W1" },
    ];
    let { publicKey, privateKey } = hssKeyGen(levels, seq(5, 24), seq(9, 16));
    for (let k = 0; k < 70; k++) {
      const msg = enc(`hss ${k}`);
      const r = hssSign(privateKey, msg);
      if (k % 31 === 0 || k === 69) expect(hssVerify(publicKey, msg, r.signature)).toBe(true);
      privateKey = r.nextKey;
    }
    expect(privateKey.keys.map((k) => k.q)).toEqual([1, 3, 6]);
  });
});

describe("tampering", () => {
  const { publicKey, privateKey } = hssKeyGen(
    [
      { lms: "LMS_SHAKE_M24_H5", ots: "LMOTS_SHAKE_N24_W4" },
      { lms: "LMS_SHA256_M24_H5", ots: "LMOTS_SHA256_N24_W4" },
    ],
    seq(0x30, 24),
    seq(0x60, 16),
  );
  const msg = enc("tamper target");
  const { signature } = hssSign(privateKey, msg);

  it("baseline verifies", () => {
    expect(hssVerify(publicKey, msg, signature)).toBe(true);
  });

  it("every single-byte flip in the signature is rejected", () => {
    for (let i = 0; i < signature.length; i++) {
      const bad = signature.slice();
      bad[i] ^= 0x01;
      expect(hssVerify(publicKey, msg, bad), `byte ${i}`).toBe(false);
    }
  });

  it("every single-byte flip in the public key is rejected", () => {
    for (let i = 0; i < publicKey.length; i++) {
      const bad = publicKey.slice();
      bad[i] ^= 0x80;
      expect(hssVerify(bad, msg, signature), `byte ${i}`).toBe(false);
    }
  });

  it("truncated / extended / wrong-level inputs are rejected", () => {
    expect(hssVerify(publicKey, msg, signature.slice(0, -1))).toBe(false);
    expect(hssVerify(publicKey, msg, new Uint8Array([...signature, 0]))).toBe(false);
    expect(hssVerify(publicKey, msg, new Uint8Array(0))).toBe(false);
    expect(hssVerify(publicKey.slice(0, -1), msg, signature)).toBe(false);
    // Claim L = 1 in the public key: Nspk + 1 no longer matches.
    const oneLevel = publicKey.slice();
    oneLevel[3] = 1;
    expect(hssVerify(oneLevel, msg, signature)).toBe(false);
  });

  it("a signature for one key does not verify under another", () => {
    const other = hssKeyGen([{ lms: "LMS_SHAKE_M24_H5", ots: "LMOTS_SHAKE_N24_W4" }, { lms: "LMS_SHA256_M24_H5", ots: "LMOTS_SHA256_N24_W4" }], seq(0x31, 24), seq(0x60, 16));
    expect(hssVerify(other.publicKey, msg, signature)).toBe(false);
  });

  it("LMS: q out of range and mismatched typecodes are rejected", () => {
    const lmsKey = lmsKeyGen("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8", seq(0, 32), seq(0, 16));
    const sig = lmsSign(lmsKey.privateKey, msg).signature;
    const q99 = sig.slice();
    q99[3] = 99;
    expect(lmsVerify(lmsKey.publicKey, msg, q99)).toBe(false);
    const otherOts = lmsKey.publicKey.slice();
    otherOts[7] = 3; // claim W4 in the public key
    expect(lmsVerify(otherOts, msg, sig)).toBe(false);
  });
});

describe("state handling", () => {
  it("a key state signs once; reuse throws, nextKey continues", () => {
    const { privateKey } = lmsKeyGen("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8", seq(3, 24), seq(4, 16));
    const r = lmsSign(privateKey, enc("a"));
    expect(() => lmsSign(privateKey, enc("b"))).toThrow(/already used/);
    expect(() => lmsSign(r.nextKey, enc("b"))).not.toThrow();
    expect(Object.isFrozen(r.nextKey)).toBe(true);
    expect(privateKey.q).toBe(0);
  });

  it("HSS state reuse throws", () => {
    const { privateKey } = hssKeyGen([{ lms: "LMS_SHA256_M24_H5", ots: "LMOTS_SHA256_N24_W2" }], seq(3, 24), seq(4, 16));
    hssSign(privateKey, enc("a"));
    expect(() => hssSign(privateKey, enc("b"))).toThrow(/already used/);
  });

  it("LMS exhaustion: 32 signatures, then refuse", () => {
    const { publicKey, privateKey } = lmsKeyGen("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1", seq(7, 24), seq(8, 16));
    let key = privateKey;
    for (let k = 0; k < 32; k++) {
      const r = lmsSign(key, enc(`x${k}`));
      if (k === 31) expect(lmsVerify(publicKey, enc(`x${k}`), r.signature)).toBe(true);
      key = r.nextKey;
    }
    expect(lmsRemaining(key)).toBe(0);
    expect(() => lmsSign(key, enc("one too many"))).toThrow(/exhausted/);
  });

  it("HSS exhaustion: 32 x 32 signatures, then refuse", () => {
    const levels = [
      { lms: "LMS_SHA256_M24_H5", ots: "LMOTS_SHA256_N24_W1" },
      { lms: "LMS_SHA256_M24_H5", ots: "LMOTS_SHA256_N24_W1" },
    ];
    let { publicKey, privateKey } = hssKeyGen(levels, seq(1, 24), seq(1, 16));
    for (let k = 0; k < 1024; k++) {
      const r = hssSign(privateKey, enc(`${k}`));
      if (k === 1023) expect(hssVerify(publicKey, enc(`${k}`), r.signature)).toBe(true);
      privateKey = r.nextKey;
    }
    expect(() => hssSign(privateKey, enc("one too many"))).toThrow(/exhausted/);
  }, 60_000);

  it("serialized LMS state resumes at the same leaf", () => {
    const { publicKey, privateKey } = lmsKeyGen("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4", seq(9, 32), seq(9, 16));
    const after = lmsSign(privateKey, enc("first")).nextKey;
    const restored = deserializeLmsPrivateKey(serializeLmsPrivateKey(after));
    expect(restored.q).toBe(1);
    const a = lmsSign(after, enc("second")).signature;
    const b = lmsSign(restored, enc("second")).signature;
    expect(toHex(b)).toBe(toHex(a));
    expect(lmsVerify(publicKey, enc("second"), b)).toBe(true);
  });

  it("serialized HSS state resumes identically, including across a child-tree switch", () => {
    const levels = [
      { lms: "LMS_SHAKE_M24_H5", ots: "LMOTS_SHAKE_N24_W2" },
      { lms: "LMS_SHA256_M24_H5", ots: "LMOTS_SHA256_N24_W2" },
    ];
    let { publicKey, privateKey } = hssKeyGen(levels, seq(2, 24), seq(3, 16));
    for (let k = 0; k < 33; k++) privateKey = hssSign(privateKey, enc("fill")).nextKey;
    const restored: HssPrivateKey = deserializeHssPrivateKey(serializeHssPrivateKey(privateKey));
    expect(restored.keys.map((k) => k.q)).toEqual([2, 1]);
    const a = hssSign(privateKey, enc("resume")).signature;
    const b = hssSign(restored, enc("resume")).signature;
    expect(toHex(b)).toBe(toHex(a));
    expect(hssVerify(publicKey, enc("resume"), b)).toBe(true);
  });

  it("rejects malformed key material", () => {
    expect(() => lmsKeyGen("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8", seq(0, 24), seq(0, 16))).toThrow(/SEED/);
    expect(() => lmsKeyGen("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8", seq(0, 32), seq(0, 15))).toThrow(/I must/);
    expect(() => hssKeyGen([], seq(0, 32), seq(0, 16))).toThrow();
    expect(u32(hssKeyGen([{ lms: 5, ots: 4 }], seq(0, 32), seq(0, 16)).publicKey, 0)).toBe(1);
  });
});
