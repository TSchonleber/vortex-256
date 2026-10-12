# VORTEX-256

An experimental symmetric block cipher with an authenticated-encryption mode, implemented in TypeScript and Rust. The two implementations produce byte-identical output.

> **Research code. Not peer reviewed. Do not use it to protect real data.**
> VORTEX-256 is a custom design. It has passed only the statistical and reduced-round tests in this repository, and those tests cannot show that a cipher is secure. For production systems, use AES-256-GCM or XChaCha20-Poly1305.

## Design

| Parameter | Value |
|---|---|
| Key | 256 bits |
| Block | 128 bits |
| Structure | 4-branch Type-2 generalized Feistel network |
| Rounds | 20 |
| S-boxes | Key-dependent 8×8, derived from the AES S-box by a key-dependent affine transform (keeps differential uniformity 4 and nonlinearity 112) |
| Diffusion | Wide-trail strategy with a near-MDS mixing layer |
| Whitening | Input and output key whitening |
| Round constants | Fractional parts of √primes, one per round |
| AEAD | CTR-mode encryption + CBC-MAC tag over AAD, ciphertext and a length block; 96-bit nonce, 128-bit tag |

## Layout

```
src/
  vortex-cipher.ts         reference implementation: key schedule, block cipher, AEAD
  vortex-cipher.test.ts    70 tests: S-box properties, round trips, avalanche, AEAD, tamper detection
  vortex-hardening.ts      constant-time helpers, masking, fault detection, SIV-style wrapper
  vortex-attack-suite.ts   20-test cryptanalysis harness (differential, linear, algebraic, timing…)
  run-vortex-analysis.ts   runs the attack suite against VORTEX-256
rust/
  src/lib.rs               Rust port (depends only on `zeroize`)
  tests/vectors.rs         checks the Rust port against the TypeScript vectors
vectors/vectors.json       block and AEAD test vectors produced by the TypeScript reference
docs/                      cryptanalysis report from the attack suite
```

## Usage

### TypeScript

```ts
import { Vortex256AEAD } from "./src/vortex-cipher";

const aead = new Vortex256AEAD(key);          // 32-byte key
const sealed = aead.seal(nonce, plaintext, aad); // 12-byte nonce, never reused with the same key
const opened = aead.open(nonce, sealed, aad);    // null if authentication fails
```

### Rust

```rust
use vortex256::{aead_encrypt, aead_decrypt};

let (ciphertext, tag) = aead_encrypt(&key, &nonce, &plaintext, &aad)?;
let plaintext = aead_decrypt(&key, &nonce, &ciphertext, &tag, &aad)?; // None if authentication fails
```

## Development

```bash
npm install
npm test             # TypeScript test suite
npm run analyze      # run the 20-test attack suite
npm run vectors      # regenerate vectors/vectors.json
cd rust && cargo test  # Rust unit tests + cross-language vector check
```

## Known limitations

- **No external cryptanalysis.** The design has not been published or reviewed. The attack suite's results are statistical evidence, not proof of security.
- **One key for encryption and authentication.** CTR and CBC-MAC share a key schedule. Standard designs derive separate keys.
- **Nonce reuse breaks confidentiality.** As with any CTR-based mode, reusing a nonce under the same key leaks the XOR of the plaintexts. `vortex-hardening.ts` includes an SIV-style wrapper for misuse resistance.
- **Constant time is best effort in JavaScript.** JIT compilation and garbage collection can undo constant-time techniques. The Rust port is the better starting point for side-channel work.

## Origin

VORTEX-256 was developed inside the CostClock AI codebase as a research project and has been extracted here as a standalone library.

## License

MIT
