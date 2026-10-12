# VORTEX-256

Post-quantum encryption and signatures for wallets, in TypeScript and Rust. Both implementations produce byte-identical
output, checked by shared test vectors.

> **Research code. Not externally reviewed.** Every primitive except the VORTEX-256 block cipher is a published standard
> with independent, audited implementations. The way they are composed here has not been reviewed by a third party yet.
> Do not protect real funds with it until it has.

## What's in it

| Module | What it does | Built on |
|---|---|---|
| **VORTEX-PQ envelope** | Encrypt to a public key | ML-KEM-1024 + X25519 hybrid KEM, HKDF-SHA3-512, VORTEX-256 / XChaCha20-Poly1305 cascade |
| **VORTEX-PQ vault** | Encrypt a secret at rest under a password | Argon2id, same key schedule and cascade |
| **LMS / HSS signatures** | Post-quantum signatures, including the RFC 9858 parameter sets | RFC 8554, RFC 9858 (SHA-256/192, SHAKE256/256, SHAKE256/192) |
| **VORTEX-256** | Experimental 128-bit block cipher with a 256-bit key | 20-round generalized Feistel network |

The full construction is specified in [docs/SPEC.md](docs/SPEC.md).

## Beyond the standards

The design starts from standard building blocks and adds margin wherever it costs little:

- **Highest NIST lattice level.** ML-KEM-1024 (category 5), where X-Wing and most TLS deployments use ML-KEM-768.
- **Hybrid key exchange.** An attacker must break both ML-KEM and X25519. The combiner binds both ciphertexts and both
  public keys.
- **Two encryption layers.** VORTEX-256 runs inside XChaCha20-Poly1305 with independent keys. The result is at least as
  strong as the stronger layer, so the experimental cipher can add security but cannot remove it.
- **Key commitment.** A ciphertext opens under exactly one key, which standard AEADs do not guarantee.
- **No nonce management.** Every message derives its own keys and nonces from a fresh KEM secret, so nonce reuse can't
  happen.
- **Hash-based signatures.** LMS/HSS rest only on the security of a hash function, the most conservative assumption in
  post-quantum cryptography. RFC 9858's 192-bit parameter sets cut signature size by about 35–40%.

## Usage

### Encrypt to a public key

```ts
import { generateKeyPair, seal, open } from "./src/pq/envelope";

const { secretKey, publicKey } = generateKeyPair();          // 32-byte seed, 1600-byte public key
const envelope = seal(publicKey, plaintext, aad);           // 1670 bytes of overhead
const message = open(secretKey, envelope, aad);             // throws OpenError on any failure
```

```rust
use vortex256::pq::{generate_key_pair, seal, open};

let (secret_key, public_key) = generate_key_pair()?;
let envelope = seal(&public_key, plaintext, aad)?;
let message = open(&secret_key, &envelope, aad)?;
```

### Lock a wallet seed with a password

```ts
import { vaultSeal, vaultOpen } from "./src/pq/vault";

const vault = await vaultSeal(utf8(password), seedBytes, utf8("wallet:main"));   // Argon2id, 256 MiB, 3 passes
const seed = await vaultOpen(utf8(password), vault, utf8("wallet:main"));
```

```rust
use vortex256::vault::{vault_seal, vault_open};

let vault = vault_seal(password, &seed, b"wallet:main")?;
let seed = vault_open(password, &vault, b"wallet:main")?;
```

### Sign with LMS / HSS

LMS is a **stateful** signature scheme: every signature consumes a one-time key, and signing twice with the same state
breaks security. Persist the updated private key **before** releasing a signature. See `src/lms/lms.ts` and
`rust/src/lms.rs` for the API.

## Layout

```
src/
  pq/envelope.ts         hybrid KEM and public-key envelope
  pq/vault.ts            password vault
  lms/lms.ts             LMS / HSS signatures (RFC 8554 + RFC 9858)
  vortex-cipher.ts       VORTEX-256 block cipher and its AEAD mode
  vortex-hardening.ts    constant-time helpers, masking, fault detection
  vortex-attack-suite.ts statistical cryptanalysis harness for VORTEX-256
rust/src/                Rust ports: pq.rs, vault.rs, lms.rs, lib.rs (VORTEX-256)
vectors/                 known-answer vectors shared by both languages, plus RFC 8554 and RFC 9858 vectors
docs/SPEC.md             normative specification
```

## Development

```bash
npm install
npm test              # TypeScript tests
npm run vectors       # regenerate the cross-language vectors
cd rust && cargo test # Rust tests, including checks against the TypeScript vectors
npm run analyze       # run the VORTEX-256 attack suite
```

## Dependencies

TypeScript: [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum),
[`@noble/curves`](https://github.com/paulmillr/noble-curves), [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers),
[`@noble/hashes`](https://github.com/paulmillr/noble-hashes).
Rust: RustCrypto's `ml-kem`, `x25519-dalek`, `chacha20poly1305`, `sha3`, `hkdf`, `argon2`.

## Known limitations

- **No external review** of the composition or of VORTEX-256.
- **No sender authentication in the envelope.** Like HPKE's base mode, it proves nothing about who sent a message. Sign
  the envelope when that matters.
- **JavaScript is not constant-time.** JIT compilation and garbage collection can undo constant-time techniques. Prefer
  the Rust implementation where side channels matter.
- **VORTEX-256 on its own** shares one key between its CTR and CBC-MAC layers. Inside the cascade this doesn't matter,
  but don't use `aeadEncrypt` directly for new designs.

## Origin

VORTEX-256 began as a research cipher inside CostClock AI. VORTEX-PQ adds the post-quantum layers around it.

## License

MIT
