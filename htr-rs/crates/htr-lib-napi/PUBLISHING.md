<!--
SPDX-FileCopyrightText: Hathor Labs
SPDX-License-Identifier: Apache-2.0
-->

# Building & publishing `@hathor/htr-lib`

`@hathor/htr-lib` is a [napi-rs](https://napi.rs) native addon (it wraps the Rust `htr-lib` crate)
with a WebAssembly fallback. This guide covers building it and publishing it to npm — both by hand
and via GitHub Actions.

## What gets published

Publishing produces **several npm packages**:

- The **main package** `@hathor/htr-lib` — only JavaScript: the entry points (`wrapper.js`,
  `browser-wrapper.mjs`, `apply-operators.cjs`) plus the generated glue (`index.js`, `index.d.ts`,
  `browser.js`, the wasi loader shims) and type defs. It declares the per-platform packages as
  `optionalDependencies`.
- One **platform package per target** under `npm/<target>/` (e.g. `@hathor/htr-lib-linux-x64-gnu`),
  each holding a single prebuilt binary (`*.node`) — or, for the wasm target, the `*.wasm` plus its
  loader. npm installs only the package matching the consumer's `os`/`cpu`/`libc`; when none match,
  it falls back to the `wasm32-wasi` package via `@napi-rs/wasm-runtime`.

The platform packages and the generated JS (`index.js`, `index.d.ts`, `browser.js`, the `*.wasi.*`
shims, `*.node`) are **not committed** — they are produced at build/publish time (see `.gitignore`).
The set of targets lives in `package.json` under `napi.targets`.

## Prerequisites

- Rust toolchain (stable) and the Rust targets you intend to build (`rustup target add <target>`).
- Node.js >= 18 and npm; run `npm ci` in this directory to get `@napi-rs/cli` and friends.
- Cross-compilation toolchains for non-host targets. CI uses the napi-rs prebuilt docker images;
  locally you need the matching linkers (or build only your host target).
- For the WebAssembly target, the WASI SDK: `export WASI_SDK_PATH=/path/to/wasi-sdk`.
- To publish: an npm automation token with publish rights to the `@hathor` scope.

## Local build (development)

```bash
npm ci
npm run build:debug   # debug .node for the host platform; regenerates index.js / index.d.ts
npm test              # ava integration tests (pretest rebuilds the addon)
```

Release build for the host platform: `npm run build` (`napi build --platform --release`).

## Versioning

```bash
npm version <patch|minor|major>   # the `version` script runs `napi version`, which keeps the
                                  # per-platform npm/<target> package versions in sync
```

Commit that bump. Publishing is triggered **manually** — the CI workflow is `workflow_dispatch`-only
(see the **CI publish** section below); pass the same version as its `version` input.

## Manual publish (all platforms)

CI automates exactly these steps; do it by hand only when CI isn't an option.

1. Create the per-platform package directories (once, or when `napi.targets` changes):
   ```bash
   npx napi create-npm-dirs
   ```
2. Build each native target (needs the matching cross toolchain):
   ```bash
   npx napi build --platform --release --target x86_64-unknown-linux-gnu
   npx napi build --platform --release --target aarch64-unknown-linux-gnu
   npx napi build --platform --release --target x86_64-apple-darwin
   npx napi build --platform --release --target aarch64-apple-darwin
   npx napi build --platform --release --target x86_64-pc-windows-msvc
   # ...and the musl targets as needed
   ```
3. Build the WebAssembly fallback (needs the WASI SDK):
   ```bash
   export WASI_SDK_PATH=/path/to/wasi-sdk
   npx napi build --platform --release --target wasm32-wasip1-threads
   ```
4. Move the built artifacts into the `npm/<target>` directories:
   ```bash
   npx napi artifacts
   ```
5. Publish. `prepublishOnly` (`napi prepublish -t npm`) publishes the per-platform packages and wires
   the main package's `optionalDependencies`; then the main package is published:
   ```bash
   npm publish --access public
   ```

## CI publish (GitHub Actions)

The workflow [`.github/workflows/htr-rs-napi-publish.yml`](../../../.github/workflows/htr-rs-napi-publish.yml)
automates the above:

- **build** — a matrix job builds one artifact per `napi.targets` entry (linux gnu/musl ×
  x64/arm64 in the napi-rs docker images, macOS x64/arm64, Windows x64, and the wasm fallback) and
  uploads each as a build artifact. The wasm job additionally uploads the generated JS glue
  (`index.js`, `index.d.ts`, `browser.js`, wasi shims) that the **main** package ships.
- **publish** — sets the version from the `version` input, downloads all artifacts, runs
  `napi create-npm-dirs` + `napi artifacts` to assemble the `npm/<target>` packages, then
  `npm publish` (which, via `prepublishOnly`, publishes the platform packages and then the main
  package). It runs in the `npm-publish` environment, so it waits for a reviewer's approval.

**How to run it** — manually from the Actions tab → *Run workflow*, with two inputs:

- **`version`** — the version to publish (an explicit version like `0.2.0`, or a bump keyword like
  `patch`/`minor`/`major`). It is applied to the published packages only — **not** committed back to
  the repo, so bump `package.json` separately to keep the repo in sync.
- **`dry-run`** — defaults to `true` (build and assemble without publishing). Set it to `false` to
  actually publish.

Either way the publish job **pauses for approval** by a Required reviewer of the `npm-publish`
environment before it starts — including dry runs. (To let dry runs through without approval, the
publish job would need to be split into an ungated dry-run job and a gated publish job.)

**One-time setup (repo admin)** — in **Settings → Environments**, create an environment named
`npm-publish` and:

- add the people allowed to publish as **Required reviewers**;
- add **`NPM_TOKEN`** (an npm automation token with publish access to `@hathor`) as an
  **environment secret**, so only this gated job can read it;
- optionally enable **Prevent self-review** (forces a second approver) and restrict the environment's
  **deployment branches** to `master`.

> **First run:** use `dry-run: true` and confirm every target builds and the `npm/<target>` packages
> assemble before a real publish. The cross-compilation matrix and the wasm artifact wiring follow
> the napi-rs reference pipeline but have not been exercised end-to-end for this repository's nested
> layout, so expect to tune a target or two on the first dry run.
