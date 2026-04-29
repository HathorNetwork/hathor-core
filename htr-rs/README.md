# htr-rs

Rust workspace for `hathor-core`.

Crates are organized as described in [Large Rust Workspaces](https://matklad.github.io/2021/08/22/large-rust-workspaces.html).

## Crates

- [`htr-lib`](crates/htr-lib) — core Rust implementations, independent of any language binding.
- [`htr-lib-py`](crates/htr-lib-py) — Python extension module (via [PyO3](https://pyo3.rs/)) exposing `htr-lib`.
- [`hathor-ct-crypto`](crates/hathor-ct-crypto) — Python extension module for confidential-transaction crypto.
- [`hathor-next`](crates/hathor-next) — **experimental** partial Rust port of `hathor-core` focused on p2p and vertex serialization. Covered by the workspace `just all` suite; also has crate-local `cargo dev-*` aliases (see [`crates/hathor-next/.cargo/config.toml`](crates/hathor-next/.cargo/config.toml)) for building against all crypto backends with `target-cpu=native`.

## Development

1. Install [Rust](https://rust-lang.org/tools/install).
2. Install [just](https://github.com/casey/just).
3. Run `just install` to install the required `cargo` extensions.
4. Run `just` to see available recipes, or `just all` to run the full local check suite (check, fmt, clippy, test, sort, audit).
