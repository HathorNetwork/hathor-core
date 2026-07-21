<!--
SPDX-FileCopyrightText: Hathor Labs
SPDX-License-Identifier: Apache-2.0
-->

## CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository context

`htr-rs/` is the Rust workspace nested inside the parent `hathor-core` repository (at `../`, a Python project). Its output is consumed from Python: the `htr-lib-py` crate compiles to a `cdylib` and is packaged as a Python extension module via [PyO3](https://pyo3.rs/) + [maturin](https://www.maturin.rs/).

CI for this workspace lives in the parent repo at `../.github/workflows/htr-rs.yml`. Jobs mirror the `just` recipes — `check`, `fmt`, `clippy`, `test` (`cargo nextest run --workspace`), `sort` (runs `cargo sort --workspace --check` — verify-only, does not rewrite), `audit`, and `node-test` (builds the `htr-lib-napi` napi addon and runs its `ava` suite). When changing the local `justfile`, keep it consistent with the workflow: `just all` runs the Rust jobs and `just all-js` adds `node-test`, together matching what CI runs.

## Commands

All commands are `just` recipes (see `justfile`) and assume you've run `just install` once to get the required cargo extensions (`cargo-nextest`, `cargo-sort`, `cargo-audit`).

- `just` — list available recipes.
- `just all` — full local Rust check suite: `check fmt clippy test sort audit`. `just all-js` adds the napi JS tests (`node-test`). Run before pushing.
- `just check` — `cargo check --workspace --all-targets --all-features`.
- `just fmt` — `cargo fmt --all -- --check` (verify only; does not modify).
- `just clippy` — `cargo clippy --workspace --all-targets --all-features`.
- `just test` — `cargo nextest run --workspace` (do not use `cargo test`; nextest is the configured runner).
- `just sort` — `cargo sort --workspace` (rewrites `Cargo.toml` in place; run when adding or reordering deps).
- `just audit` — RustSec advisory scan.

Single test: `cargo nextest run -p <crate> <test_name_substring>` (e.g. `cargo nextest run -p htr-lib-py test_sum_as_string`).

`RUSTFLAGS="-D warnings"` is set by the justfile, so warnings fail every recipe. Fix them; do not `#[allow(...)]` to silence them.

## Architecture and invariants

- **Workspace layout.** `Cargo.toml` at the workspace root declares `members = ["crates/*"]`, `resolver = "3"`. By default, Rust-level dependencies are pinned under `[workspace.dependencies]` and crates point to them via `{ workspace = true }` (e.g. `num-bigint`, `num-traits`). The exception is language-specific binding dependencies, which belong in their binding crate — `pyo3`, for instance, is pinned directly in `htr-lib-py` because that is the only crate crossing the PyO3 boundary; promote such a dependency to the workspace if another crate ever needs it. Every crate inherits lints via `[lints] workspace = true` — keep it that way when adding crates.
- **Overflow checks are on in every profile**, including `release` and `bench`. This is deliberate: integer overflow must panic, never wrap. Do not disable `overflow-checks` or reach for `wrapping_*` / `as` casts to work around a panic — fix the arithmetic.
- **`elided_lifetimes_in_paths = "deny"`** at the workspace level. Write explicit lifetimes on paths (e.g. `Bound<'_, PyModule>`, not `Bound<PyModule>`).
- **64-bit only.** `crates/htr-lib/src/lib.rs` emits `compile_error!` on non-64-bit targets so `usize` semantics stay consistent across platforms. Because `htr-lib-py` depends on `htr-lib`, the guard also gates the Python extension build. Code may assume `usize` is 64 bits.
- **`htr-lib-py` is built as both `cdylib` and `rlib`.** The `cdylib` is what maturin packages for Python; the `rlib` lets future Rust crates in this workspace depend on `htr-lib-py` directly. Keep both `crate-type` entries.
- **Python surface.** `htr_lib.pyi` is the hand-maintained type stub for the extension module. When you add or change a `#[pyfunction]` / `#[pymodule]` item, update `htr_lib.pyi` to match — Python type checkers consume it, not the Rust source.
- **`maturin-generate-ci` is kept for reference only.** Wheel building/uploading is not currently wired into CI; don't assume it runs.

## Code guidelines

- Comments and docstrings describe current state, not history. Do not mention removed approaches, prior implementations, or "no longer does X" — that belongs in commit messages.
- Always prefer `.expect("…")` over `.unwrap()` in production code. The message should state the invariant that justifies the panic, not restate the operation — so a panicking stack trace tells the next reader *what was assumed to hold*, not just *what blew up*. Tests can use `.unwrap()` freely — a failing test already points at the line.
- Pre-allocate collections when the size is known or tightly upper-bounded.
- Bind complex expressions to a variable before using them as the operand of a wrapping construct — a `for` loop iteree, an `Ok(…)` / `Some(…)` / `Err(…)` wrapper, a function argument, etc. Long method chains or multi-line matches buried inside a wrapper make the wrapper itself hard to see and the contents hard to read.
- Most non-trivial functions and methods should have a clear, concise docstring. Docstrings may be omitted when the behavior is obvious from the name and signature.
- Add comments for non-obvious code, and use them to explain **WHY**, not **WHAT**. The WHAT is the code itself; the WHY is the hidden constraint, invariant, or surprising decision that a future reader cannot recover from the code alone.
- A helper function should earn its name. Inline it when it has a single caller, a trivial body, a name that restates the mechanics rather than naming a concept, and no independent-testing gain. Keep it separate when any of these hold: multiple callers, the name captures a non-obvious invariant or domain concept, the helper has its own edge cases or error reasoning worth quarantining, or the body is long enough that inlining would bloat the caller past a screen.
- In tests, prefer asserting on exact values and exact error messages (e.g. `assert_eq!`, not `contains`), and exact rendered output (pin the full string). `contains`-style assertions silently pass when the surrounding text shifts, drifts, or regresses.
