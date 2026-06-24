# @hathor/htr-lib

TypeScript/JavaScript binding for the Hathor `htr-lib` Rust library, built with
[napi-rs](https://napi.rs). Exposes `UnsignedAmount`, `SignedAmount`, and
`TokenAmountVersion`.

## Install

```bash
npm install @hathor/htr-lib
```

Prebuilt native binaries are published per platform; environments without a
matching native binary fall back to the `wasm32-wasi` package
(via `@napi-rs/wasm-runtime`).

## Usage

```ts
import { UnsignedAmount, SignedAmount, TokenAmountVersion } from '@hathor/htr-lib'

// Configure the V1->V2 normalization factor once, before constructing any V1 amount.
UnsignedAmount.setNormalizationFactor(2, 18)

const a = UnsignedAmount.fromV2(5n)
const b = UnsignedAmount.fromV1(1n)        // normalized to 10^16
const sum = a.add(b)                     // UnsignedAmount (always V2)
console.log(sum.normalized())            // bigint

const bal = new SignedAmount(-3n)
const amount = new SignedAmount(5n).toUnsigned()  // throws if negative
```

### Operators

Arbitrary-precision values cross the boundary as JS `bigint`.

- **Ordering** works with native operators: `a < b`, `a > b`, `a <= b`, `a >= b`
  (for two `UnsignedAmount`s or two `SignedAmount`s). These also type-check in TypeScript.
- **Equality and arithmetic must use methods** — JavaScript cannot overload them:
  - Use `a.eq(b)` / `a.ne(b)`, **not** `a == b` / `a === b` (those are reference
    identity at runtime, and silently wrong).
  - Use `a.add(b)` / `a.sub(b)` / `b.neg()`, **not** `a + b` / `a - b` (those
    coerce to `bigint` and drop the wrapper type).
- **Mixed comparisons** like `amount < 5n` do not type-check; compare two wrapper
  values, or use `a.lt(b)` / `a.compare(b)` (`-1 | 0 | 1`).
- **Balance ± amount** — `SignedAmount.add` / `.sub` also accept an `UnsignedAmount`
  (`balance.add(amount)`), normalizing it to the V2 unit first and returning a
  `SignedAmount` (which may be negative after `.sub`).

`String(x)` / template literals return the Rust `Debug` form (e.g.
`V2 { normalized: 5 }`, `SignedAmount(-3)`).

## Develop

```bash
npm install
npm run build:debug   # builds the native addon, regenerates index.js / index.d.ts
npm test              # ava integration tests (pretest rebuilds the addon)
cargo nextest run -p htr-lib-napi   # Rust unit tests (conversion + version-mapping helpers)
```

> The workspace CI uses `cargo nextest run --workspace` and `RUSTFLAGS="-D warnings"`
> (see `../../justfile` — `just all`). Match it with `cargo nextest run -p
> htr-lib-napi` and `cargo clippy -p htr-lib-napi --all-targets --all-features`.

## Build & publish (manual)

There is no CI publishing yet; releases are built and published by hand.

1. **Generate the per-platform npm package directories** (once, or when targets change):

   ```bash
   npx napi create-npm-dirs
   ```

   This creates `npm/<target>/` packages from `napi.targets` in `package.json`,
   each declaring its `os`/`cpu`/`libc` so npm installs only the matching one.

2. **Build each native target** (requires the matching cross-compilation toolchain):

   ```bash
   npx napi build --platform --release --target x86_64-unknown-linux-gnu
   npx napi build --platform --release --target aarch64-unknown-linux-gnu
   npx napi build --platform --release --target x86_64-apple-darwin
   npx napi build --platform --release --target aarch64-apple-darwin
   npx napi build --platform --release --target x86_64-pc-windows-msvc
   # ...and the musl targets as needed
   ```

3. **Build the WebAssembly fallback** (needs the WASI SDK; set `WASI_SDK_PATH`):

   ```bash
   export WASI_SDK_PATH=/path/to/wasi-sdk
   npx napi build --platform --release --target wasm32-wasip1-threads
   ```

   Consumers of the WASM package need `@napi-rs/wasm-runtime` (already a
   dependency). Browser usage requires cross-origin isolation
   (`Cross-Origin-Opener-Policy: same-origin`,
   `Cross-Origin-Embedder-Policy: require-corp`) because the threads target uses
   `SharedArrayBuffer`.

4. **Move build artifacts into the npm directories:**

   ```bash
   npx napi artifacts
   ```

5. **Publish** (scoped package -> public access). Publish each `npm/<target>`
   package and then the main package:

   ```bash
   npm publish --access public        # from each npm/<target>/ dir, then the root
   ```

   `npm run prepublishOnly` (`napi prepublish -t npm`) prepares the optional
   dependency wiring for the main package.

## What is committed vs generated

- Committed: Rust sources, `wrapper.js`, `wrapper.d.ts`, `package.json`, `README.md`.
- Generated (gitignored): `index.js`, `index.d.ts`, `browser.js`, `*.node`, `npm/`,
  and the WASI loader shims (`*.wasi.cjs`, `*.wasi-browser.js`, `wasi-worker*.mjs`).
