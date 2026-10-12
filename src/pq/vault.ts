/**
 * VORTEX-PQ vault — password-based encryption for secrets at rest (wallet seeds, key files).
 *
 * Argon2id stretches the password; the result feeds the same HKDF-SHA3-512 key schedule,
 * key commitment and VORTEX-256 / XChaCha20-Poly1305 cascade as the public-key envelope.
 * Symmetric 256-bit keys keep a 128-bit margin against Grover's algorithm, so no KEM is
 * needed here. Normative description: docs/SPEC.md, "Vault".
 */

import { argon2idAsync } from "@noble/hashes/argon2.js";
import { sha3_512 } from "@noble/hashes/sha3.js";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";
import { ascii, bytesEqual, cascadeDecrypt, cascadeEncrypt, deriveMessageKeys, OpenError } from "./envelope";

const MAGIC = ascii("VXPW");
const VERSION = 0x01;
const SUITE_ARGON2ID = 0x02;
const SALT_SIZE = 32;
const HEADER_SIZE = 4 + 1 + 1 + 4 + 4 + 1 + SALT_SIZE; // 47
export const VAULT_OVERHEAD = HEADER_SIZE + 32 + 2 * 16; // 111

export interface Argon2Params {
  /** Memory in KiB. */
  m: number;
  /** Passes. */
  t: number;
  /** Lanes. */
  p: number;
}

/** Default cost: 256 MiB, 3 passes. Roughly a second or two on a laptop in native code, slower in JS. */
export const DEFAULT_PARAMS: Argon2Params = { m: 262_144, t: 3, p: 1 };
/** Floor enforced on seal and open: OWASP's 2024 Argon2id minimum (19 MiB, 2 passes). */
export const MIN_PARAMS: Argon2Params = { m: 19_456, t: 2, p: 1 };
/** Ceiling enforced on seal and open, so a crafted header can't demand unbounded memory or time. */
export const MAX_PARAMS: Argon2Params = { m: 2_097_152, t: 64, p: 16 };

function header(params: Argon2Params, salt: Uint8Array): Uint8Array {
  const h = new Uint8Array(HEADER_SIZE);
  h.set(MAGIC, 0);
  h[4] = VERSION;
  h[5] = SUITE_ARGON2ID;
  const dv = new DataView(h.buffer);
  dv.setUint32(6, params.m);
  dv.setUint32(10, params.t);
  h[14] = params.p;
  h.set(salt, 15);
  return h;
}

function checkParams(params: Argon2Params, allowWeak: boolean): void {
  const ok = Number.isInteger(params.m) && Number.isInteger(params.t) && Number.isInteger(params.p) && params.p >= 1 &&
    params.m >= 8 * params.p && params.t >= 1 && params.m <= MAX_PARAMS.m && params.t <= MAX_PARAMS.t && params.p <= MAX_PARAMS.p;
  if (!ok) throw new Error("VORTEX-PQ vault: invalid Argon2 parameters");
  if (!allowWeak && (params.m < MIN_PARAMS.m || params.t < MIN_PARAMS.t)) {
    throw new Error("VORTEX-PQ vault: Argon2 parameters below the minimum");
  }
}

async function stretch(password: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
  return argon2idAsync(password, salt, { m: params.m, t: params.t, p: params.p, dkLen: 64, maxmem: 2 ** 32 - 1 });
}

export interface VaultOptions {
  params?: Argon2Params;
  /** Test vectors only. */
  salt?: Uint8Array;
  /** Test vectors only: permits parameters below MIN_PARAMS. */
  insecureAllowWeakParams?: boolean;
}

/** Encrypts `plaintext` under `password`. The password should be UTF-8 encoded by the caller. */
export async function vaultSeal(
  password: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  opts: VaultOptions = {}
): Promise<Uint8Array> {
  const params = opts.params ?? DEFAULT_PARAMS;
  checkParams(params, opts.insecureAllowWeakParams === true);
  const salt = opts.salt ?? randomBytes(SALT_SIZE);
  if (salt.length !== SALT_SIZE) throw new Error(`VORTEX-PQ vault: salt must be ${SALT_SIZE} bytes`);
  const h = header(params, salt);
  const k = deriveMessageKeys(await stretch(password, salt, params), sha3_512(h));
  return concatBytes(h, cascadeEncrypt(k, plaintext, aad));
}

/** Decrypts a vault. Throws `OpenError` for a wrong password, tampering, or a malformed vault. */
export async function vaultOpen(
  password: Uint8Array,
  vault: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  opts: Pick<VaultOptions, "insecureAllowWeakParams"> = {}
): Promise<Uint8Array> {
  if (vault.length < VAULT_OVERHEAD) throw new OpenError();
  const h = vault.subarray(0, HEADER_SIZE);
  if (!bytesEqual(h.subarray(0, 4), MAGIC) || h[4] !== VERSION || h[5] !== SUITE_ARGON2ID) throw new OpenError();
  const dv = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const params = { m: dv.getUint32(6), t: dv.getUint32(10), p: h[14] };
  try {
    checkParams(params, opts.insecureAllowWeakParams === true);
  } catch {
    throw new OpenError();
  }
  const salt = h.slice(15, 15 + SALT_SIZE);
  const k = deriveMessageKeys(await stretch(password, salt, params), sha3_512(h));
  return cascadeDecrypt(k, vault.subarray(HEADER_SIZE), aad);
}
