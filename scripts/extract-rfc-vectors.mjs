// Extracts the HSS/LMS test vectors from the RFC 8554 / RFC 9858 plain-text files.
// usage: node scripts/extract-rfc-vectors.mjs <rfc8554.txt> <rfc9858.txt> <outdir>
import { readFileSync, writeFileSync } from "node:fs";

const [, , f8554, f9858, outDir] = process.argv;

// Turn a block of RFC lines into ordered [label, hex] entries. The first token
// that is pure lowercase hex (>= 8 chars) is the value; tokens before it form the
// label (empty label = continuation of the previous value).
function entries(lines) {
  const out = [];
  for (const line of lines) {
    const toks = line.trim().split(/\s+/);
    // Labeled values are >= 8 hex chars; a bare continuation may be shorter
    // (e.g. the final "2e0a" line of the RFC 8554 messages).
    const isHex = (t, min) => new RegExp(`^[0-9a-f]{${min},}$`).test(t) && t.length % 2 === 0;
    const k = isHex(toks[0], 2) ? 0 : toks.findIndex((t) => isHex(t, 8));
    if (k < 0) continue;
    const label = toks.slice(0, k).join(" ");
    if (label === "") {
      if (!out.length) throw new Error("continuation without label: " + line);
      out[out.length - 1][1] += toks[k];
    } else out.push([label, toks[k]]);
  }
  return out;
}

function buildCase(name, lines) {
  const es = entries(lines);
  const iLevels = es.findIndex(([l]) => l === "levels");
  const iMsg = es.findIndex(([l]) => l === "Message");
  const iNspk = es.findIndex(([l]) => l === "Nspk");
  if (iLevels < 0 || iMsg < iLevels || iNspk < iMsg) throw new Error("bad structure in " + name);
  const priv = es.slice(0, iLevels);
  const c = { name };
  const seeds = priv.filter(([l]) => l === "SEED").map(([, v]) => v);
  const ids = priv.filter(([l]) => l === "I").map(([, v]) => v);
  c.seed = seeds[0] ?? "";
  c.i = ids[0] ?? "";
  c.seed2 = seeds[1] ?? "";
  c.i2 = ids[1] ?? "";
  c.publicKey = es.slice(iLevels, iMsg).map(([, v]) => v).join("");
  c.message = es[iMsg][1];
  if (iNspk !== iMsg + 1) throw new Error("unexpected entries between message and signature in " + name);
  c.signature = es.slice(iNspk).map(([, v]) => v).join("");
  return c;
}

function splitCases(lines, startRe, endRe, headRe) {
  const start = lines.findLastIndex((l) => startRe.test(l));
  let end = lines.findIndex((l, i) => i > start && endRe.test(l));
  if (end < 0) end = lines.length;
  const body = lines.slice(start + 1, end);
  const groups = [];
  for (const l of body) {
    const m = headRe(l);
    if (m && (!groups.length || groups[groups.length - 1].key !== m.key)) groups.push({ key: m.key, title: m.title, lines: [] });
    else if (groups.length) groups[groups.length - 1].lines.push(l);
  }
  return groups.map((g) => buildCase(g.title, g.lines));
}

const l8554 = readFileSync(f8554, "utf8").split("\n");
const c8554 = splitCases(l8554, /^Appendix F\.\s+Test Cases/, /^Acknowledgements/, (l) => {
  const m = /^\s+Test Case (\d+) /.exec(l);
  return m && { key: m[1], title: "RFC 8554 Test Case " + m[1] };
});
const l9858 = readFileSync(f9858, "utf8").split("\n");
const c9858 = splitCases(l9858, /^Appendix A\.\s+Test Cases/, /^Acknowledgements/, (l) => {
  const m = /^(A\.\d+)\.\s+(.*)$/.exec(l);
  return m && { key: m[1], title: "RFC 9858 " + m[1] + " " + m[2].trim() };
});

const dump = (source, cases) => {
  const body = cases
    .map((c) => "    {\n" + Object.entries(c).map(([k, v]) => `      "${k}": ${JSON.stringify(v)}`).join(",\n") + "\n    }")
    .join(",\n");
  return `{\n  "source": ${JSON.stringify(source)},\n  "cases": [\n${body}\n  ]\n}\n`;
};
writeFileSync(outDir + "/rfc8554.json", dump("RFC 8554 Appendix F (extracted from rfc8554.txt)", c8554));
writeFileSync(outDir + "/rfc9858.json", dump("RFC 9858 Appendix A (extracted from rfc9858.txt)", c9858));
for (const c of [...c8554, ...c9858]) console.log(c.name, c.publicKey.length / 2, c.message.length / 2, c.signature.length / 2);
