# `@hathor/ct-crypto-wasm`

Browser-compatible (wasm-bindgen) build of the Hathor confidential-transaction
crypto primitives.

This crate is the **verifier-only** sibling of
[`@hathor/ct-crypto-node`](https://github.com/HathorNetwork/hathor-ct-crypto):

- ✅ `deriveAssetTag`, `deriveTag`, `htrAssetTag`
- ✅ `createAssetCommitment` (blinded asset generator for FullShielded)
- ✅ `createCommitment` (Pedersen value commitment)
- ✅ `createTrivialCommitment`

Range-proof rewind, ECDH and surjection-proof creation are **not** exposed —
anyone holding the cleartext `value` / `vbf` / `abf` already has the rewound
output, so those primitives would only inflate the WASM artifact for browser
consumers.

The Node-side `@hathor/ct-crypto-node` package keeps the full surface for
wallet-lib's signing / scanning paths.

## Build

The crate is consumed via npm (`npm install @hathor/ct-crypto-wasm`); to
build the artifact yourself you need:

- Rust with the `wasm32-unknown-unknown` target
- An **unwrapped** clang with the wasm32 backend (nix's wrapped clang
  injects host-only flags; emscripten's `emcc` rejects bare wasm32)
- `wasm-pack`

The repo ships a flake that wires all three:

```sh
nix develop --command ./scripts/build-wasm.sh
```

That produces a publishable artifact at `pkg/`. To publish:

```sh
cd pkg && npm publish --access public
```

## Tests

```sh
cargo test                              # native unit tests (generators, pedersen)
nix develop --command wasm-pack test --node   # wasm bindings (optional)
```

## Layout

```
src/
  lib.rs           # exports + module gate
  error.rs         # HathorCtError
  types.rs         # TokenUid, COMMITMENT_SIZE, GENERATOR_SIZE
  generators.rs    # asset-tag derivation + asset-commitment construction
  pedersen.rs      # Pedersen commitment math
  wasm_bindings.rs # wasm-bindgen surface
flake.nix          # dev shell (wasm-pack + clang-unwrapped + llvm-ar)
scripts/build-wasm.sh   # builds + patches pkg/package.json with the npm-scoped name
```

The crypto core (`generators.rs`, `pedersen.rs`) is duplicated from the
sibling `hathor-ct-crypto` repo so the WASM crate publishes, audits and
builds independently. Behavioral parity with the NAPI bindings is enforced
by wallet-lib's `__tests__/shielded/provider.test.ts` round-trip suite.
