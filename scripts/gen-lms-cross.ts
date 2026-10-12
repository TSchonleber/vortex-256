import { writeFileSync } from "node:fs";
import * as L from "../src/lms/lms";
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const seq = (start: number, len: number) => Uint8Array.from({ length: len }, (_, i) => (start + i) & 0xff);
const enc = (s: string) => new TextEncoder().encode(s);
const cases = [
  { name: "HSS L=1 LMS_SHAKE_M24_H5 / LMOTS_SHAKE_N24_W8, first signature", levels: [["LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8"]], seed: seq(0xa0, 24), I: seq(0xc0, 16), index: 0, message: enc("vortex-256 LMS cross-language vector 1\n") },
  { name: "HSS L=1 LMS_SHAKE_M24_H5 / LMOTS_SHAKE_N24_W8, signature #7", levels: [["LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8"]], seed: seq(0xa0, 24), I: seq(0xc0, 16), index: 7, message: enc("vortex-256 LMS cross-language vector 2\n") },
  { name: "HSS L=2 SHAKE_M24_H5/SHAKE_N24_W8 over SHA256_M24_H5/SHA256_N24_W4, signature #33 (second child tree)", levels: [["LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8"], ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"]], seed: seq(0x10, 24), I: seq(0x50, 16), index: 33, message: enc("vortex-256 HSS cross-language vector 3\n") },
];
const out = cases.map((c) => {
  const levels = c.levels.map(([lms, ots]) => ({ lms, ots }));
  let { publicKey, privateKey } = L.hssKeyGen(levels, c.seed, c.I);
  for (let k = 0; k < c.index; k++) privateKey = L.hssSign(privateKey, enc("filler")).nextKey;
  const { signature } = L.hssSign(privateKey, c.message);
  if (!L.hssVerify(publicKey, c.message, signature)) throw new Error("self-verify failed");
  return {
    name: c.name,
    levels: c.levels.map(([lms, ots]) => `${L.LMS[lms].type}/${L.LMOTS[ots].type}`).join(","),
    seed: toHex(c.seed), i: toHex(c.I), index: String(c.index), message: toHex(c.message),
    publicKey: toHex(publicKey), signature: toHex(signature),
  };
});
const body = out.map((c) => "    {\n" + Object.entries(c).map(([k, v]) => `      "${k}": ${JSON.stringify(v)}`).join(",\n") + "\n    }").join(",\n");
writeFileSync("vectors/lms-cross.json",
  `{\n  "source": "vortex-256 src/lms/lms.ts (hssKeyGen from SEED/I; 'index' = signatures made before this one; 'levels' = LMS/LM-OTS typecodes, top first)",\n  "cases": [\n${body}\n  ]\n}\n`);
console.log("ok", out.map((c) => c.signature.length / 2));
