# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Hathor Core is the official full-node implementation for Hathor Network, a Proof-of-Work network whose **transactions and blocks both form a DAG** (not a linear chain). Conflict resolution is by accumulated weight, and "voidance" (a non-empty `voided_by` metadata set on a vertex) — not deletion — is how the consensus marks losing branches.

This working tree is on the `feat/shielded-outputs` branch and adds **confidential / shielded transaction outputs** on top of the regular v1/v2 transaction format. Shielded outputs are attached via a `ShieldedOutputsHeader` (no new tx version), and the cryptographic primitives (Pedersen commitments, range proofs, ECDH, surjection proofs) live in the Rust crate `hathor-ct-crypto/`. See `hathor-ct-crypto/SHIELDED-OUTPUTS-CLIENT-GUIDE.md` for the wallet/explorer integration model.

## Workspace Layout

The repo is multi-language. Three components live side by side and are wired into the Python package via path/editable installs:

- `hathor/`, `hathor_cli/`, `hathor_tests/` — main Python project (this `pyproject.toml`).
- `hathorlib/` — local Python sub-package (`hathorlib = {path = "hathorlib", develop = true}`); owns base tx objects, network configs (`hathorlib/hathorlib/conf/{mainnet,testnet,nano_testnet}.yml`), etc. **Genesis tests load YAMLs from this path, not from `hathor/conf/`.**
- `hathor-ct-crypto/` — Rust crate for shielded-output crypto. Built as a Python extension via PyO3 + maturin (feature `python`) and as a Node addon via NAPI (feature `napi`). Imported in Python as `hathor_ct_crypto`.
- `htr-rs/` — separate Rust workspace (its own `justfile` and CLAUDE.md). The `htr-lib` crate is a PyO3 cdylib pulled into Python as `htr-lib = {path = "htr-rs/crates/htr-lib", develop = true}`. **It has its own conventions** (overflow checks on in all profiles, 64-bit only, `nextest` not `cargo test`, `RUSTFLAGS=-D warnings`) — read `htr-rs/CLAUDE.md` before editing anything inside it.

## Common Commands

Run from this directory (`hathor-core/`) unless noted.

```bash
# Install Python deps (also pulls hathorlib + htr-lib editable)
poetry install

# Build the shielded-output Rust extension into the poetry venv
make build-shielded-crypto       # runs `maturin develop --release ... --features python`

# Lint + type-check (ruff + mypy + custom checks + yamllint)
make check

# Format (ruff isort fix)
make fmt

# All tests (cli + lib + genesis + custom + ci + shielded)
make tests

# Quick lib tests, slow tests excluded, fail fast
make tests-quick

# Topical suites
make tests-nano                  # nanocontracts
make tests-cli                   # CLI
make tests-shielded              # builds the Rust crate, runs cargo + Python binding tests
make tests-genesis               # runs against each network YAML in hathorlib/

# Single test file / single test
pytest hathor_tests/path/to/test_file.py
pytest hathor_tests/path/to/test_file.py::TestClass::test_method

# Mypy only (use dmypy for repeated runs — daemon-backed, much faster)
make mypy
make dmypy

# Run a node
poetry run hathor-cli run_node --testnet --data ../data --status 8080
```

If RocksDB import fails after a system update (common on macOS Homebrew rotations), run `make fix-rocksdb` — it rebuilds the wheel against the current shared library.

## Architecture

### Big picture

```
HathorManager (hathor/manager.py)
  central orchestrator: lifecycle (INITIALIZING -> READY), tx/block ingress, propagation

ConsensusAlgorithm (hathor/consensus/)
  DAG consensus, voidance tracking, accumulated-weight conflict resolution
  block + transaction rules; PoW and PoA modes

ConnectionsManager (hathor/p2p/manager.py)
  peer lifecycle (HELLO -> PEER_ID -> READY), Sync-V2 streaming

VerificationService (hathor/verification/)
  two-phase: validate_basic (no deps) then validate_full
  type-specific verifiers: blocks, transactions, nanocontracts, shielded outputs

VertexHandler (hathor/vertex_handler/)
  ingress pipeline: validate -> consensus.unsafe_update -> save -> relay
```

Transaction ingress flow:

```
HathorManager.push_tx(tx)
  -> vertex_handler.on_new_relayed_vertex(tx)
       -> verification_service.validate_full(tx)
       -> consensus.unsafe_update(tx)
       -> tx_storage.save_transaction(tx)
  -> connections.send_tx_to_peers(tx)
```

### Cross-cutting patterns

- **Builder pattern.** Components are wired via the fluent `Builder` in `hathor/builder/builder.py`. Prefer extending the builder over constructing managers directly in tests.
- **Pub/Sub.** Cross-component signaling goes through `PubSubManager` with the `HathorEvents` enum — not direct callbacks.
- **Voidance, not deletion.** A vertex is "executed" when `voided_by` is empty; otherwise it is voided. Reorganization toggles this set; it does not remove vertices.
- **Storage backends.** RocksDB is the production backend; an in-memory backend is used in tests. Both implement the same `TransactionStorage` interface in `hathor/transaction/storage/`.
- **Nanocontracts.** Lightweight Python "blueprints" executed by `hathor/nanocontracts/runner/` against a typed storage. They participate in normal consensus and have their own verifiers.
- **Shielded outputs.** Attached via header, not a new tx version. `hathor/crypto/` holds the Python-side glue; the heavy lifting is in the `hathor_ct_crypto` Rust extension. Tests in `hathor_tests/crypto/` require `make build-shielded-crypto` to have been run first.

## Testing notes

- `pytest -n auto` (parallel) is the default — see `addopts` in `pyproject.toml`.
- Slow tests are marked `@pytest.mark.slow`; `make tests-quick` skips them.
- Genesis tests must run with the right network YAML; the Makefile recipe sets `HATHOR_TEST_CONFIG_YAML` to each `hathorlib/hathorlib/conf/*.yml` and runs single-process (`-n0`).
- Shielded-output tests in `hathor_tests/crypto/test_shielded_bindings.py` import the compiled Rust extension; rebuild with `make build-shielded-crypto` after touching `hathor-ct-crypto/src/`.
- Custom checks live in `extras/custom_checks.sh`; custom tests in `extras/custom_tests/` (run via `extras/custom_tests.sh`).

## Code style

- **Formatting/lint:** `ruff` (replaces flake8) — line length 119, isort via `ruff check --select I --fix`. Run `make fmt`.
- **Type checking:** `mypy` with the pydantic + mypy-zope plugins. Stricter rules are opted in per-module via `[[tool.mypy.overrides]]` for `consensus`, `feature_activation`, `event`, `verification`, and several test packages — additions in those areas need full type annotations.
- **YAML:** `yamllint .` is part of `make check`.
- **Rust (hathor-ct-crypto):** `cargo fmt`, `cargo clippy -- -D warnings`. The `htr-rs/` workspace has its own (stricter) rules — see `htr-rs/CLAUDE.md`.
