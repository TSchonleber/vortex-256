# VORTEX-PQ v1 — Hybrid Post-Quantum Envelope

VORTEX-PQ encrypts a message to a recipient's public key so that recovering the plaintext requires breaking
**both** a lattice KEM (ML-KEM-1024) **and** elliptic-curve Diffie-Hellman (X25519), and then **both** a standard
AEAD (XChaCha20-Poly1305) **and** VORTEX-256.

Every primitive except VORTEX-256 is a published standard with independent implementations. VORTEX-256 sits inside
the cascade, so it can add security but cannot remove it.

## Design goals beyond the standards

| Property | Typical standard (e.g. X-Wing, HPKE) | VORTEX-PQ v1 |
|---|---|---|
| Lattice parameter set | ML-KEM-768 (NIST category 3) | ML-KEM-1024 (category 5) |
| Hybrid | X25519 + ML-KEM | X25519 + ML-KEM |
| Combiner binds | X25519 ciphertext and public key | both ciphertexts and both public keys |
| Combiner output | 256 bits | 512 bits (SHA3-512) |
| KDF | HKDF-SHA-256 | HKDF-SHA3-512 |
| Symmetric layer | one AEAD | cascade of two independent AEADs with independent keys |
| Key commitment | no | yes, 256-bit commitment checked before decryption |
| Nonces | caller supplied | derived per message; reuse is impossible because each message has a fresh KEM secret |
| Transcript binding | partial | header, KEM ciphertext and recipient public key all bound into the KDF and both AEADs |

## Notation

- `||` is byte concatenation; `[a:b]` is a half-open byte slice.
- `LABEL` = ASCII `"VORTEX-PQ-v1"` (12 bytes).
- `SHAKE256(x, n)`, `SHA3-256(x)`, `SHA3-512(x)` per FIPS 202.
- `ML-KEM-1024.KeyGen_internal(d, z)`, `ML-KEM-1024.Encaps_internal(ek, m)`, `ML-KEM-1024.Decaps(dk, c)` per FIPS 203.
- `X25519(k, u)` per RFC 7748; `9` is the base point.
- `HKDF-SHA3-512(salt, ikm, info, L)` per RFC 5869 instantiated with SHA3-512.
- `VORTEX-AEAD(k, n, m, ad)` is `aeadEncrypt` from `src/vortex-cipher.ts` (ciphertext followed by 16-byte tag).
- `XChaCha20-Poly1305(k, n, m, ad)` per draft-irtf-cfrg-xchacha (ciphertext followed by 16-byte tag).

## Sizes

| Item | Bytes |
|---|---|
| Secret key (seed) | 32 |
| Public key `pk = pk_M || pk_X` | 1568 + 32 = 1600 |
| KEM ciphertext `ct = ct_M || ct_X` | 1568 + 32 = 1600 |
| Envelope overhead | 6 + 1600 + 32 + 16 + 16 = 1670 |

## Key generation

```
KeyGen(seed):                                  # seed: 32 uniformly random bytes
  e     = SHAKE256(LABEL || "/keygen" || seed, 96)
  dk_M, pk_M = ML-KEM-1024.KeyGen_internal(d = e[0:32], z = e[32:64])
  sk_X  = e[64:96]
  pk_X  = X25519(sk_X, 9)
  return seed, pk_M || pk_X
```

The secret key is only the 32-byte seed. All component keys are re-derived from it.

## Hybrid KEM

```
Encaps(pk, eseed):                             # eseed: 64 uniformly random bytes
  pk_M, pk_X = pk[0:1568], pk[1568:1600]
  ct_M, ss_M = ML-KEM-1024.Encaps_internal(pk_M, m = eseed[0:32])
  ct_X  = X25519(eseed[32:64], 9)
  ss_X  = X25519(eseed[32:64], pk_X)
  abort if ss_X is all zero
  ss    = Combine(ss_M, ss_X, ct_M, ct_X, pk_M, pk_X)
  return ct_M || ct_X, ss

Decaps(seed, ct):
  re-derive dk_M, pk_M, sk_X, pk_X from seed
  ct_M, ct_X = ct[0:1568], ct[1568:1600]
  ss_M  = ML-KEM-1024.Decaps(dk_M, ct_M)      # implicit rejection: a bad ct_M yields a random ss_M
  ss_X  = X25519(sk_X, ct_X)
  abort if ss_X is all zero
  return Combine(ss_M, ss_X, ct_M, ct_X, pk_M, pk_X)

Combine(ss_M, ss_X, ct_M, ct_X, pk_M, pk_X) =
  SHA3-512(LABEL || "/combine" || ss_M || ss_X || ct_X || pk_X || SHA3-256(ct_M) || SHA3-256(pk_M))
```

The shared secret depends on both component secrets. An attacker who breaks only one of ML-KEM or X25519 still
faces a uniformly random contribution from the other.

## Envelope

```
Seal(pk, plaintext, aad, eseed):
  header = "VXPQ" || 0x01 (version) || 0x01 (suite)          # 6 bytes
  ct, ss = Encaps(pk, eseed)
  th     = SHA3-512(header || ct || pk)                        # transcript hash
  okm    = HKDF-SHA3-512(salt = LABEL, ikm = ss, info = th, L = 132)
  k1, n1 = okm[0:32],   okm[32:44]                            # VORTEX-256 key and nonce
  k2, n2 = okm[44:76],  okm[76:100]                           # XChaCha20-Poly1305 key and nonce
  commit = okm[100:132]
  ad     = th || aad
  inner  = VORTEX-AEAD(k1, n1, plaintext, ad)
  outer  = XChaCha20-Poly1305(k2, n2, inner, ad)
  return header || ct || commit || outer

Open(seed, envelope, aad):
  parse header, ct, commit, outer; reject unknown version or suite
  pk     = public key re-derived from seed
  ss     = Decaps(seed, ct)
  th, okm, k1, n1, k2, n2 as in Seal
  reject unless commit == okm[100:132]  (constant time)
  inner  = XChaCha20-Poly1305-Open(k2, n2, outer, th || aad)  or reject
  return VORTEX-AEAD-Open(k1, n1, inner, th || aad)           or reject
```

All failures return the same error so the decrypting party is not an oracle for which layer failed.

## Vault (password-based, suite 0x02)

For secrets at rest, such as a wallet's seed. No KEM is needed: a 256-bit symmetric key already keeps a 128-bit margin
against Grover's algorithm. The vault reuses the envelope's key schedule, commitment and cascade.

```
VaultSeal(password, plaintext, aad, params = {m, t, p}, salt):   # salt: 32 random bytes
  require MIN <= params <= MAX
  header = "VXPW" || 0x01 || 0x02 || u32be(m) || u32be(t) || u8(p) || salt          # 47 bytes
  key    = Argon2id(password, salt, m KiB, t passes, p lanes, version 0x13, 64-byte output)
  okm    = HKDF-SHA3-512(salt = LABEL, ikm = key, info = SHA3-512(header), L = 132)
  return header || commit || outer        # commit and outer exactly as in the envelope, with th = SHA3-512(header)

VaultOpen(password, vault, aad):
  parse header; reject unknown version or suite; reject params outside [MIN, MAX]
  re-derive and verify as in Open
```

| Parameters | Memory | Passes | Lanes |
|---|---|---|---|
| Default | 256 MiB | 3 | 1 |
| Minimum (OWASP 2024) | 19 MiB | 2 | 1 |
| Maximum (anti-DoS) | 2 GiB | 64 | 16 |

The cost parameters sit in the authenticated header, so they cannot be lowered without the password. The maximum keeps a
crafted vault from forcing unbounded memory or time on the device that opens it.

## Security notes

- **Post-quantum:** confidentiality rests on ML-KEM-1024 against quantum adversaries. The symmetric keys are 256 bits,
  leaving a 128-bit margin against Grover's algorithm.
- **Hybrid:** if ML-KEM-1024 is broken classically, X25519 still protects the message against non-quantum attackers.
- **Cascade:** the outer layer is a standard AEAD. VORTEX-256 adds an independent second layer; a flaw in it does not
  weaken the outer layer, because the two keys are independent HKDF outputs.
- **Key commitment:** the commitment is a 256-bit HKDF output bound to the shared secret and transcript, so an envelope
  cannot be crafted to decrypt validly under two different recipient keys.
- **No sender authentication:** like HPKE base mode, VORTEX-PQ v1 proves nothing about who sent a message. Pair it with
  a signature (see the LMS/HSS module) when the sender must be authenticated.
- **Not reviewed:** this composition has not had an external review. Treat it as research until it has.
