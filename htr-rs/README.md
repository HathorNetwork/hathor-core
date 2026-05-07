# htr-rs

Rust workspace for `hathor-core`.

Crates are organized as described in [Large Rust Workspaces](https://matklad.github.io/2021/08/22/large-rust-workspaces.html).

## Crates

- [`htr-lib`](crates/htr-lib) — Python extension module (via [PyO3](https://pyo3.rs/)) exposing Rust implementations to `hathor-core`.

## Development

1. Install [Rust](https://rust-lang.org/tools/install).
2. Install [just](https://github.com/casey/just).
3. Run `just install` to install the required `cargo` extensions.
4. Run `just` to see available recipes, or `just all` to run the full local check suite (check, fmt, clippy, test, sort, audit).
