# Shielded Transactions — Reference-Branch Restructure & PR Plan

**Branch:** `feat/shielded-outputs-rebased` (the *reference* branch — squashed source of truth for the
full shielded feature).
**Goal:** restructure the reference branch into its final target architecture, then slice a sequence of
reviewable PRs onto `master` until the branch diff is empty.

This supersedes the older `docs/plans/shielded-pr-split.md` for sequencing decisions. That document's
PRs 1, 2, and 4-headers (`#1702`) have already landed on `master`.

---

## Why restructure first

The reference branch is our source of truth for the *final shape* of the code. If we slice PRs from a
structurally-wrong branch, every PR inherits the wrong structure and we pay twice (review the wrong
location, then a churny "move it" PR later). So we correct the branch once — **Phase 0** — then slice.

Two structural problems on the branch today:

1. **Rust crypto lives in a parallel crate.** The branch added `hathor-ct-crypto/` — its own
   `Cargo.toml`, `Makefile`, `build.rs`, separate CI, plus a second `maturin develop` in the Dockerfile —
   duplicating the already-merged `htr-rs/` workspace (which exposes the `htr_lib` pyo3 module and has its
   own CI `htr-rs.yml`). The crypto belongs **inside `htr-rs`**.

2. **Client-facing code lives in hathor-core.** The Python crypto wrappers and decryption helper sit in
   `hathor/crypto/shielded/**`, but clients need them to *build* shielded txs. The data model + headers
   already live in hathorlib with core re-exporting (the `#1702` pattern). More belongs in **hathorlib**.

---

## Decision log

| Decision | Resolution |
|---|---|
| `get_header_id()` / `headers/base.py` scaffold | **Drop** — zero callers; the canonical-ordering check it was for was never implemented |
| `validate_shielded_crypto_available` + `SHIELDED_CRYPTO_AVAILABLE` + `_bindings.py` try/except + builder hook | **Drop** — vestigial; once crypto is a crate in htr-rs it is always built, like any hard dep |
| hathorlib crypto → `htr_lib` imports | **Hard / eager** (not lazy) |
| `recover_shielded_secrets` placement | **hathorlib crypto package** — keeps the general parse path native-lib-free (decision A) |
| `hathor/crypto/shielded/**` | **Move to `hathorlib/crypto/shielded/`** |
| Rust `hathor-ct-crypto/` | **Fold into `htr-rs/`** |
| htr-rs crate layout | **Separate pure-Rust `htr-ct-crypto` crate** + pyo3 binding in `htr-lib` (exposed as `htr_lib`) |
| NAPI/Node bindings | **Keep**, as a **dedicated crate** `htr-ct-crypto-node` |

### Note: pyo3 version

`hathor-ct-crypto` uses **pyo3 0.22** (`PyBytes::new_bound`, `IntoPy`, …). The htr-rs workspace pins
**pyo3 0.28.3**. Folding `ffi.rs` into `htr-lib` therefore requires porting ~686 lines from the 0.22 to
the 0.28 API (`new_bound` → `new`, `IntoPy`/`to_object` → `IntoPyObject`, etc.). Verify with a real
`maturin develop` + the binding tests.

---

## Phase 0a — fold Rust into htr-rs

Target workspace layout:

```
htr-rs/crates/
  htr-ct-crypto/        # pure Rust crypto — pedersen, rangeproof, surjection,
                        #   ecdh, balance, generators, error, types  (NO bindings)
  htr-ct-crypto-node/   # dedicated NAPI binding over htr-ct-crypto  (+ node-tests/)
  htr-lib/              # pyo3 #[pymodule] htr_lib — wraps htr-ct-crypto, exposes a `shielded` surface
```

Steps:
1. Create `htr-ct-crypto/` from `hathor-ct-crypto/src/{pedersen,rangeproof,surjection,ecdh,balance,
   generators,error,types}.rs`; pure-Rust `Cargo.toml` (secp256k1-zkp, rand, sha2, hex, thiserror;
   dev: proptest, criterion); carry over `benches/`. Add to workspace `members` (already `crates/*`).
2. Port `ffi.rs` pyo3 logic into `htr-lib` (0.22 → 0.28), exposing the crypto functions/classes through
   the `htr_lib` module. Decide flat vs `htr_lib.shielded` submodule (lean submodule for namespacing).
3. Create `htr-ct-crypto-node/` from `napi_bindings.rs` + `node-tests/` as a NAPI crate over
   `htr-ct-crypto`.
4. Delete `hathor-ct-crypto/` entirely.
5. Rewire builds: revert the Dockerfile `COPY hathor-ct-crypto` + extra `maturin develop`; drop the
   parallel CI workflow; keep `htr-rs.yml`. Root `pyproject.toml` already depends on `htr_lib`.
6. Rewire Python: delete `hathor/crypto/shielded/_bindings.py`; crypto wrappers `import htr_lib`
   directly (this also executes the drop of `validate_shielded_crypto_available`/`AVAILABLE`).

Verify: `cargo build`/`cargo test` in htr-rs, `maturin develop` builds `htr_lib`, the shielded binding
tests pass against `htr_lib`.

---

## Phase 0b — hathor → hathorlib boundary

**Bucket 1 — MOVE to hathorlib**
- `hathor/crypto/shielded/{commitment,range_proof,surjection,ecdh,balance,asset_tag,generators}.py`
  + `__init__` → **`hathorlib/crypto/shielded/`** (new module; hard `import htr_lib`).
- `recover_shielded_secrets()` → **hathorlib crypto package** (NOT the parse-path `shielded_tx_output.py`).
- Consequence: delete core `hathor/transaction/shielded_tx_output.py` shim; repoint its ~9 importers to
  `hathorlib`.

**Bucket 2 — STAY in hathor-core (node-only):** verification, consensus, indexes, sync, event model,
DAG builder, HTTP API resources, node wallet, builder/CLI, nanocontracts, core vertex parsers.

**Bucket 3 — MIRROR into hathorlib (data-model accessors; follow `#1702`):** `shielded_outputs` property,
`is_shielded()`, `has_shielded_inputs()`, `has_unshield_balance_header()`, `get_unshield_balance_header()`,
`excess_blinding_factor`; `token_info.calculate_fee(..., shielded_fee=)` (low priority). `scripts/opcode`
and `execute` shielded checks stay core (execution is node-only); only the `OutputMode` import re-points.

Open: exact Bucket-3 scope (mirror all now vs defer `calculate_fee`).

---

## PR sequence (after Phase 0)

1. **mint/melt header ser/deser** — hathorlib data model + core re-export + parser wiring; gated; no verification semantics.
2. **shielded crypto lib** — htr-rs `htr-ct-crypto` crate + `htr_lib` pyo3 surface + NAPI crate + build/CI + hathorlib Python wrappers; tests live and green.
3. **integration (#7)** — indexes, sync, API, events, DAG builder (relocate `calculate_shielded_fee` next to the data model so #7 doesn't depend on #5).
4. **verification (#5)** — security-critical balance/proofs/dispatch.
5. **wallet (#6)** — node wallet shielded UTXO discovery/decryption.

Also pending, independent of the stack: a **twisted-log-formatting + typing** chore PR (`cli/util.py`,
`run_node.py`, `events_simulator/*`, `test_twisted_log_format.py`); and dropping the
`hathorlib/utils/address.py` noqa revert + the scratch files (`_audit*`, `_designs`, etc.).
