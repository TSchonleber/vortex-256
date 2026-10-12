import { readFileSync } from "node:fs";
import { OpenError } from "./envelope";
import { MIN_PARAMS, VAULT_OVERHEAD, vaultOpen, vaultSeal } from "./vault";

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const weak = { params: { m: 64, t: 1, p: 1 }, insecureAllowWeakParams: true };

describe("VORTEX-PQ vault", () => {
  it("round-trips with a password", async () => {
    const v = await vaultSeal(enc("correct horse"), enc("abandon abandon ... about"), enc("wallet"), weak);
    expect(v.length).toBe(25 + VAULT_OVERHEAD);
    expect(new TextDecoder().decode(await vaultOpen(enc("correct horse"), v, enc("wallet"), weak))).toBe("abandon abandon ... about");
  });

  it("rejects a wrong password, wrong aad, and tampering", async () => {
    const v = await vaultSeal(enc("pw"), enc("secret"), new Uint8Array(0), weak);
    await expect(vaultOpen(enc("pW"), v, new Uint8Array(0), weak)).rejects.toThrow(OpenError);
    await expect(vaultOpen(enc("pw"), v, enc("x"), weak)).rejects.toThrow(OpenError);
    for (const i of [0, 5, 7, 14, 20, 47, 60, 79, v.length - 1]) {
      const t = v.slice();
      t[i] ^= 1;
      await expect(vaultOpen(enc("pw"), t, new Uint8Array(0), weak), `byte ${i}`).rejects.toThrow(OpenError);
    }
  });

  it("refuses weak parameters unless explicitly allowed", async () => {
    await expect(vaultSeal(enc("pw"), enc("s"), new Uint8Array(0), { params: { m: 64, t: 1, p: 1 } })).rejects.toThrow();
    const v = await vaultSeal(enc("pw"), enc("s"), new Uint8Array(0), weak);
    await expect(vaultOpen(enc("pw"), v)).rejects.toThrow(OpenError);
  });

  it("accepts the minimum parameters", async () => {
    const v = await vaultSeal(enc("pw"), enc("s"), new Uint8Array(0), { params: MIN_PARAMS });
    expect(hex(await vaultOpen(enc("pw"), v))).toBe(hex(enc("s")));
  }, 60_000);

  it("matches the stored known-answer vectors", async () => {
    const file = JSON.parse(readFileSync(new URL("../../vectors/vortex-pq-vault.json", import.meta.url), "utf8"));
    for (const x of file.vectors) {
      const opts = { params: x.params, salt: unhex(x.salt), insecureAllowWeakParams: true };
      const v = await vaultSeal(unhex(x.password), unhex(x.plaintext), unhex(x.aad), opts);
      expect(hex(v)).toBe(x.vault);
      expect(hex(await vaultOpen(unhex(x.password), v, unhex(x.aad), opts))).toBe(x.plaintext);
    }
  });
});
