# Parallel Input Script Verification (benchmark-first)

## Context

When a new transaction is added to the DAG, the slowest verification step is input script verification — ECDSA secp256k1 via the `cryptography` lib (OpenSSL). Today it runs fully serially on the Twisted reactor thread: `VerificationService.validate_full()` → `TransactionVerifier.verify_inputs()` → `_verify_inputs()` loops over inputs and calls `script_eval()` per input (`hathor/verification/transaction_verifier.py:136-190`).

**Goal**: fan out the per-input script evaluations of a single transaction to a worker pool (scatter/gather; the top-level call stays synchronous — no async refactor). **Benchmark first** to decide threads vs processes; the production code is built around an executor abstraction so the choice is data-driven. Note: OpenSSL releases the GIL during EC verify, so threads are expected to win (no pickling), but the benchmark validates this.

**Key facts (verified)**:
- Script eval is a pure function of: `txin.data`, spent output script, `tx.get_sighash_all_data()` (cached, idempotent — `hathor/transaction/vertex_parser/vertex_serializer.py:183`), `tx.timestamp` (timelock), `opcodes_version`; plus, for V1-only `op_find_p2pkh`, spent-output value and tx outputs. No storage access; per-call stack/logs.
- Exact extras usage in `hathor/transaction/scripts/opcode.py`: line 195 (`tx.timestamp`), line 266 (`tx.get_sighash_all_data()`), lines 515-517 (`op_find_p2pkh`: `spent_tx`/`txin`/`tx`). `op_checkmultisig` delegates to `op_checksig` and reads `get_global_settings()` (works in subprocesses: `HATHOR_CONFIG_YAML` is in env).
- Second caller of `_verify_inputs` classmethod: `hathor/consensus/consensus.py:549` — must keep working; stays serial (pool param defaults to None).
- Error-ordering semantics to preserve (interleaved, per input in order): size → spent-tx fetch → timestamp → script → ConflictingInputs (conflict for input *i* is checked AFTER input *i*'s script).
- Existing pattern: `manager.py:237/314/360` owns/starts/stops `pow_thread_pool`. We follow the ownership pattern but use `concurrent.futures` (ThreadPoolExecutor/ProcessPoolExecutor share the `Executor` interface — exactly the abstraction needed; the call blocks the reactor thread either way, so no Deferred plumbing).

## Stage 1 — Executor abstraction + detached payload (no behavior change)

**New: `hathor/verification/script_verification_pool.py`**
- `ScriptVerificationMode` enum: `DISABLED` (serial, default) | `THREADS` | `PROCESSES`.
- `ScriptVerificationJob` — frozen, picklable, storage-free dataclass: `input_index`, `input_data: bytes`, `output_script: bytes`, `sighash_all_data: bytes`, `tx_timestamp: int`, `spent_output_value: int`, `tx_outputs: tuple[tuple[int, bytes], ...]` (shared per-tx tuple; empty for opcodes V2+ since `op_find_p2pkh` is V1-only), `opcodes_version`.
- `build_script_verification_job(tx, txin, spent_tx, opcodes_version, *, shared_outputs)`.
- `execute_script_verification_job(job) -> ScriptError | None` — top-level (picklable) worker fn; returns the error instead of raising so the gather is deterministic and avoids cross-process exception-chain pickling issues. Calls `raw_script_eval()` with a `DetachedUtxoScriptExtras`.
- `ScriptVerificationPool(mode, num_workers, min_inputs=2)` with `start()` (create executor; `mp_context='spawn'` for processes — never fork a process holding RocksDB/Twisted threads; warm-up job), `stop()` (`shutdown(wait=False, cancel_futures=True)`), `run_jobs(jobs) -> list[ScriptError | None]` (serial loop if disabled or `len(jobs) < min_inputs`; else one future per job, gathered in input order).

**Modify: `hathor/transaction/scripts/execute.py`** (lines 28-37)
- Add accessors on `ScriptExtras`/`UtxoScriptExtras`: `get_sighash_all_data()`, `timestamp`, `spent_output_value`, `iter_outputs() -> (value, script)`.
- Add `DetachedUtxoScriptExtras` — frozen dataclass over the primitive fields implementing the same accessors; fully picklable, no tx/txin/spent_tx.

**Modify: `hathor/transaction/scripts/opcode.py`**
- Line 195 → `context.extras.timestamp`; line 266 → `context.extras.get_sighash_all_data()`; lines 514-527 (`op_find_p2pkh`) → use `extras.spent_output_value` + `extras.iter_outputs()` (it only reads `output.script`/`output.value`). The `assert isinstance(..., UtxoScriptExtras)` checks (lines 194, 514) accept both variants (small shared base class).

Thread mode uses the same detached jobs as process mode — one uniform code path.

## Stage 2 — Benchmark (decision gate)

**New: `extras/benchmarking/script_verification/benchmark_script_verification.py`** (`extras/benchmarking/` already exists). Runnable via `uv run python ... [--workers 2,4,8] [--repeat 50] [--input-counts 1,2,8,32,255] [--kinds p2pkh,multisig]`.
- Builds realistic signed txs without storage/manager: `ec.generate_private_key(ec.SECP256K1())`, synthetic spent tx, sign sighash per input, `P2PKH.create_input_data(...)`; multisig follows the exact pattern in `hathor_tests/tx/test_multisig.py:97-102` (`generate_multisig_redeem_script` + `MultiSig.create_input_data`).
- Arms run through the actual production `pool.run_jobs()` path: (a) serial baseline (plus a serial line via today's `script_eval` to show the detached-extras delta is nil), (b) THREADS, (c) PROCESSES. Pools created/warmed once before timing.
- Matrix: input counts {1,2,8,32,255} × {P2PKH, 2-of-3 multisig} × workers {2,4,8} (capped at cpu_count). Report median + p90 ms/tx, µs/input, speedup vs serial.
- Decision outputs: threads-vs-processes winner, `min_inputs` crossover, optimal worker count. Record results in the PR.

## Stage 3 — Production wiring

**`hathor/verification/transaction_verifier.py`** (core change, lines 136-190):
- `__init__` gains kw-only `script_verification_pool: ScriptVerificationPool | None = None`; `_verify_inputs` gains kw-only `script_pool=None` (so `consensus.py:549` keeps working, serial).
- New 3-phase flow:
  1. *Main thread, in input order*: size check / `get_spent_tx` / index assert / timestamp check / collect job / ConflictingInputs set check. On the first non-script failure at index k, record it as `stop_error` and stop collecting (jobs are 0..k-1; for ConflictingInputs, 0..k).
  2. *Scatter/gather*: sighash precomputed once (implicit in job building); `results = pool.run_jobs(jobs)` or serial loop.
  3. *Deterministic merge, in input order*: for each job i, raise `InvalidInputData(results[i]) from results[i]` if failed (same wrap as today's `verify_script`, lines 186-190); then a recorded conflict at i; finally `stop_error`. This reproduces today's interleaved semantics exactly — lowest-index failure wins, identical exception types/messages.
- Keep `verify_script()` as-is for compatibility.

**`hathor/verification/vertex_verifiers.py`**: `create_defaults` (line 44) / `create` (line 71) gain kw-only pool param, forwarded to `TransactionVerifier` (line 94).

**`hathor/builder/builder.py`**: fluent `set_script_verification_config(mode, num_workers, min_inputs)` + `_get_or_create_script_verification_pool()` (default DISABLED); pass into `VertexVerifiers.create_defaults` (~line 631) and `HathorManager` (~line 259).

**`hathor/manager.py`**: store the pool (near line 237); `start()` it in `start()` (~line 314, so process-spawn cost is paid at boot) and `stop()` it in `stop()` (~lines 360-361).

**CLI** (`hathor_cli/run_node.py`, `run_node_args.py`, `hathor_cli/builder.py`):
- `--script-verification-workers N` (default 0 = serial), `--script-verification-executor {process,thread}` (default `process`), `--x-script-verification-min-inputs N` (hidden, default 4 from benchmark).
- This is node-operational policy → CLI flags, not network YAML settings.

### Benchmark decision (Stage 2 — recorded in `extras/benchmarking/script_verification/RESULTS.md`)

The benchmark **inverted the original hypothesis**: `cryptography`'s `verify()` does NOT release the GIL on
current CPython, so **threads never help and usually thrash** (e.g. 32 inputs: 0.27–0.42x). **Processes win**,
growing with input count (4 inputs 1.4–1.7x, 32 inputs 2–3.5x, 255 inputs up to 6x @8 workers). The detached
payload adds no overhead vs `script_eval`. Crossover is crisp at **4 inputs** (3 inputs ≈ break-even).

Chosen defaults: executor=**process**, **min_inputs=4**, **num_workers=4**. Threads stay available behind the
flag but are never recommended on current CPython.

## Stage 4 — Tests

**New: `hathor_tests/tx/test_parallel_script_verification.py`**
1. Equivalence matrix parametrized over `{disabled, threads, processes}` (processes marked `slow`): valid multi-input P2PKH and 2-of-3 multisig; bad signature at first/middle/last input; oversized input_data at k combined with bad script at j<k and j>k (asserts interleaving); TimestampError; ConflictingInputs at k vs script error at j<k (script wins) and j>k (conflict wins). Assert exception type AND message identical to serial. Build txs via existing helpers (`hathor/simulator/utils.py:54` `add_new_blocks`, wallet, `test_multisig.py` pattern).
2. Merge-algorithm unit tests with stubbed job results (no crypto) covering every ordering branch.
3. Pool robustness: reuse across many sequential calls, start/stop/start, `min_inputs` threshold respected (spy executor asserts serial path for 1-input txs).
4. Manager lifecycle starts/stops the pool.

**Existing suite with pool on**: opt-in env knob `HATHOR_TEST_SCRIPT_VERIFICATION=thread:4` read in `hathor_tests/unittest.py` `get_builder` (~line 169); CI job runs `test_verification.py`, `test_multisig.py`, `test_scripts.py` with it (xdist-compatible).

## Verification

1. `uv run pytest hathor_tests/tx/test_parallel_script_verification.py`
2. `uv run pytest hathor_tests/tx/test_verification.py hathor_tests/tx/test_multisig.py hathor_tests/tx/test_scripts.py` — serial and with `HATHOR_TEST_SCRIPT_VERIFICATION=thread:4`
3. `uv run python extras/benchmarking/script_verification/benchmark_script_verification.py` — confirm speedup, pick executor kind / workers / min_inputs from results
4. `uv run mypy` and full `uv run pytest -n auto`
5. Manual smoke: `run_node` on testnet with `--script-verification-workers 4`, observe sync working and CPU profiler numbers for `verify_inputs`

## Rollout

1. **Release 1, default OFF** (`DISABLED`): zero change for operators; benchmark committed alongside.
2. Decide executor from benchmark — expectation: **threads** (GIL released in OpenSSL EC verify, no pickling/spawn complexity). Process mode stays behind the flag as escape hatch.
3. **Release 2, default ON** after testnet soak: `threads`, `num_workers = min(4, cpu_count)`, `min_inputs` from measured crossover. 1-input txs always run inline.

Implementation order: Stage 1 → Stage 2 (benchmark, record numbers) → Stage 3 → Stage 4.
