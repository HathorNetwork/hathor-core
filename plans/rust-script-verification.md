# Rust batch script verification (no-GIL, real threads)

> **Part of a two-plan effort.** This plan is the **first slice**: it builds the Rust crypto + opcode interpreter and
> the batch pattern for per-input *script* verification. `plans/rust-verification-service.md` then **reuses this crate**
> to move the whole storage-free verification set into Rust and parallelize it across vertices in the sync pipeline for
> the larger TPS win. Build this one first.

## Context

Input signature verification is the slowest step when adding a tx to the DAG. The **process-pool** approach is already merged (see "Foundation already shipped" below) and works, but it is fundamentally bounded:

- `cryptography`'s ECDSA `verify()` **holds the GIL**, so threads thrash → we were forced into *processes*, which pay pickling + IPC + subprocess-spawn + N-interpreter memory.
- Benchmark (24-core box): best ~3× (p2pkh) to ~7× (multisig) at 8–12 workers, **regressing past ~12** (24 workers ≈ 1.3–3×, often worse than 4) due to oversubscription + the serial dispatch thread. It also *loses* on the common 1–3-input txs.

**Rust removes every one of those limits.** No GIL → real OS threads (rayon) in-process, **no pickling/IPC/spawn**. `libsecp256k1` is several× faster per-verify than OpenSSL's generic ECDSA and supports batch verification. The crossover drops toward 1 input and scaling stays clean. The repo already has a working **PyO3 + maturin** crate (`htr-rs/crates/htr-lib`, imported as `htr_lib`, wired into uv/poetry + CI, currently only a demo `sum_as_string`) — the binding scaffolding is done.

**Goal**: move the per-input script *evaluation* into Rust as a single GIL-released, rayon-parallel batch call, exposed behind the existing `ScriptVerificationPool` as a new `RUST` mode. **Python stays the authoritative reference**; correctness is guaranteed by differential testing + shadow mode, because any Rust↔OpenSSL divergence on a single signature is a chain split.

### Foundation already shipped (Stages 1–4, merged)
`ScriptVerificationPool` / `ScriptVerificationJob` / `execute_script_verification_job` in `hathor/verification/script_verification_pool.py`; the storage-free `DetachedUtxoScriptExtras` and narrowed opcode accessors in `hathor/transaction/scripts/{execute,opcode}.py`; the 3-phase `_verify_inputs_parallel` merge in `hathor/verification/transaction_verifier.py`; CLI/builder/manager wiring; equivalence tests in `hathor_tests/tx/test_parallel_script_verification.py`; benchmark in `extras/benchmarking/script_verification/`. **The Rust work reuses all of this**: the same `ScriptVerificationJob` payload is the Rust input, and the deterministic merge / error-ordering logic is unchanged — only Phase 2 (`run_jobs`) gains a Rust path.

## Consensus surface the Rust must replicate bit-for-bit

Reference: `hathor/transaction/scripts/{execute,opcode,multi_sig,p2pkh}.py` and `hathorlib/utils/address.py`.

- **Interpreter** (`execute_eval`/`raw_script_eval`): merge `input_data + output_script`, evaluate the merged opcode stream, then `evaluate_final_stack` (valid iff exactly one item left and it equals `1`). **MultiSig two-pass**: if `output_script` matches the MultiSig regex, eval `redeem_script_tail + output_script`, then eval `get_multisig_data(input_data)` (`multi_sig.py:154` — strips the PUSHDATA1/len framing of the redeem script). Replicate `get_multisig_redeem_script_pos`/`get_multisig_data` byte handling exactly.
- **Pushdata/parsing** (`get_script_op`, `execute.py:166`): opcodes 1–75 push N bytes; `OP_PUSHDATA1` (0x4C) pushes len-prefixed; `OP_0..OP_16` push ints 0–16; invalid opcode / out-of-data → reject.
- **Opcode set** — always: `OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_GREATERTHAN_TIMESTAMP, OP_CHECKSIG, OP_CHECKMULTISIG`. **V1 only**: `OP_CHECKDATASIG, OP_DATA_STREQUAL, OP_DATA_GREATERTHAN, OP_DATA_MATCH_VALUE, OP_FIND_P2PKH` (gated exactly as `execute_op_code`, `opcode.py:656-663`).
- **Crypto** (the critical risk):
  - `OP_CHECKSIG`: pubkey must be compressed — first byte `0x02/0x03` (`is_pubkey_compressed`), 33 bytes, valid on-curve point (else `ScriptError`); message = `sighash_all_data` (already a sha256 digest), verified as `ECDSA(SHA256)` over it (i.e. secp256k1 ECDSA of `sha256(sighash_all_data)`); signature is **DER**. Invalid sig → push `0` (not an error). `OP_CHECKDATASIG` (V1): same verify over arbitrary stack `data`; invalid → `OracleChecksigFailed`.
  - `OP_CHECKMULTISIG`: pops `N`, N pubkeys, `M`, M sigs; greedy in-order match (each sig advances through remaining pubkeys); enforces `MAX_MULTISIG_PUBKEYS/SIGNATURES` from settings. Delegates each check to `OP_CHECKSIG` semantics.
  - `OP_HASH160` = `ripemd160(sha256(x))`. `OP_GREATERTHAN_TIMESTAMP` compares `tx_timestamp` (from the job) to a big-endian u32.
  - **DER acceptance must match OpenSSL exactly**: OpenSSL's `verify` does **not** enforce low-S and tolerates some non-canonical DER; the Rust `secp256k1` crate is strict by default and has `from_der_lax`. The exact parse mode + S-normalization policy that reproduces OpenSSL's accept/reject set is determined empirically by the differential fuzz below — this is the single most important correctness item.
- **What stays in Python (Phase 1, unchanged)**: `MAX_INPUT_DATA_SIZE`, `get_spent_tx`, timestamp-ordering, conflicting-inputs, and `verify_sigops_input` (cheap, runs first). Only the script eval moves to Rust.
- **Error model**: Rust returns per-input `Valid | Invalid{reason}`; Python maps `Invalid → ScriptError(reason)`, which the existing merge wraps as `InvalidInputData`. Consensus cares only about **accept/reject + the `InvalidInputData` type** (e.g. `consensus.py:551` branches on it) — the human-readable log text legitimately differs from Python's and is **not** part of consensus.

## Architecture

**Rust (`htr-rs/crates/htr-lib`)** — new modules `src/script/{mod,interpreter,opcodes,crypto}.rs`, registered in `src/lib.rs`. Cargo deps to add: `secp256k1` (libsecp256k1), `sha2`, `ripemd`, `rayon`, `thiserror`. Settings constants (`MAX_MULTISIG_*`, opcodes version gating) passed in per call or as job fields — do **not** read global settings in Rust.
- PyO3 entry: `verify_scripts_batch(jobs) -> list[VerifyResult]`, where each job carries exactly the `ScriptVerificationJob` fields (`input_data, output_script, sighash_all_data, tx_timestamp, spent_output_value, tx_outputs, opcodes_version` + the two multisig limits). Wrap the CPU work in `Python::allow_threads(|py| ...)` and parallelize with `rayon::par_iter`. Result enum `{ Valid, Invalid(String) }` (string is debug-only). Update `htr_lib.pyi`.

**Python (`hathor/verification/script_verification_pool.py`)**:
- Add `ScriptVerificationMode.RUST`. In `run_jobs`, when mode is `RUST`, call `htr_lib.verify_scripts_batch(jobs)` (single in-process call — no executor, no `min_inputs` gating needed, though keep a tiny inline path for 0/1 jobs). Map results to `list[ScriptError | None]`; the rest of `_verify_inputs_parallel`'s merge is untouched.
- CLI: extend `--script-verification-executor` choices with `rust` (`hathor_cli/run_node.py` + `_create_script_verification_pool` in `hathor_cli/builder.py`). Likely becomes the recommended/default executor once validated.

## Consensus-exactness strategy (the core deliverable)

1. **Python is the reference and default**; Rust is opt-in until proven.
2. **Differential harness** (`hathor_tests/tx/test_rust_script_verification.py`): run every job through both `execute_script_verification_job` (Python) and `htr_lib.verify_scripts_batch` (Rust); assert identical accept/reject. Corpus = all existing `test_scripts.py`/`test_multisig.py` vectors + generated cases (valid/invalid P2PKH, M-of-N multisig, checkdatasig, timelocks, find_p2pkh, truncated/oversized/malformed scripts, wrong-prefix/short pubkeys, extra-stack-item, empty-stack) + a **property-based fuzzer** (random bytes as input_data/output_script → both must agree).
3. **Signature-acceptance fuzz** (dedicated): compare OpenSSL `verify` vs Rust secp256k1 over `(pubkey, sig, msg)` triples, explicitly covering non-canonical DER, high-S, trailing/leading-zero bytes, point-at-infinity, off-curve pubkeys. Pick the DER/S policy that matches OpenSSL across the whole corpus; freeze it as a regression test.
4. **Shadow mode**: an optional runtime mode where Python (authoritative) and Rust both verify and mismatches are logged + metric'd (crash-on-mismatch on testnet). Soak on testnet before making Rust authoritative.

## Rollout

- **Phase A** — Rust interpreter + crypto + `cargo nextest` unit tests mirroring `test_scripts.py`/`test_multisig.py` vectors. (CI: `.github/workflows/htr-rs.yml` already runs nextest/clippy/fmt/audit.)
- **Phase B** — PyO3 batch binding + Python `RUST` mode + the differential pytest harness (Python↔Rust over the corpus + fuzz). Gate merge on zero mismatches.
- **Phase C** — add a `RUST` arm to `extras/benchmarking/script_verification/benchmark_script_verification.py`; confirm the expected win (esp. at 1–3 inputs and vs the process pool).
- **Phase D** — shadow mode on testnet; then flip default executor to `rust`. Process/thread modes remain behind the flag as fallback.

## Critical files

- New Rust: `htr-rs/crates/htr-lib/src/script/{mod,interpreter,opcodes,crypto}.rs`, `src/lib.rs` (register pyfunction), `Cargo.toml` (deps), `htr_lib.pyi`.
- Python: `hathor/verification/script_verification_pool.py` (RUST mode + call + result mapping); `hathor_cli/run_node.py` + `hathor_cli/builder.py` (`rust` executor choice); optional shadow hook in `hathor/verification/transaction_verifier.py`.
- Tests/bench: `htr-rs/...` cargo tests; `hathor_tests/tx/test_rust_script_verification.py` (differential + fuzz); extend the benchmark + `RESULTS.md`.
- Reference (read, do not change semantics): `hathor/transaction/scripts/{execute,opcode,multi_sig,p2pkh}.py`, `hathorlib/utils/address.py`.

## Verification

1. `cd htr-rs && just all` (check/fmt/clippy/nextest/audit) — Rust unit vectors pass.
2. `uv run pytest hathor_tests/tx/test_rust_script_verification.py` — differential harness: **zero** Python↔Rust accept/reject mismatches over corpus + fuzz; dedicated signature-acceptance fuzz green.
3. `uv run pytest hathor_tests/tx/test_verification.py hathor_tests/tx/test_multisig.py hathor_tests/tx/test_scripts.py` with `HATHOR_TEST_SCRIPT_VERIFICATION=rust:<n>`.
4. `uv run python extras/benchmarking/script_verification/benchmark_script_verification.py` with the `RUST` arm — confirm it beats serial at 1 input and beats the process pool everywhere; record in `RESULTS.md`.
5. `uv run mypy` + full `uv run pytest -n auto`.
6. Manual: `run_node` testnet with `--script-verification-executor rust` (+ shadow mode) — observe sync + zero mismatches + `verify_inputs` CPU profile.
