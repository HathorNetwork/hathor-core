# S3S4 — Verify: Rust script interpreter + parallel verification

> **What S3S4 is:** the verification stage — proving a tx is valid before it's saved. The
> expensive part is **per-input script/signature verification**: for each input, run Hathor's
> little script language (P2PKH / MultiSig / data opcodes) and check the ECDSA secp256k1
> signature. In a transparent workload this is the classic bottleneck — our Phase-1 numbers
> showed inputs dominate (`~base + 2.6 ms·(I−1)`).
>
> **Bottom line up front:** this is the **headline** of the PR, and it's really **two
> intertwined optimizations**: (A) the script interpreter is rewritten in **Rust** and folded
> into a single **GIL-released "fused" batch call**, and (B) verification is **parallelized**
> across a worker pool. Together they drive *all* Rust-side verification down to **~4.8 µs/tx
> (~2% of the pipeline)** — verification stops being "the last big rock." A surprising
> benchmark result reshaped the design (below). Citations are to the PR clone at `optimized-ref/`.

---

## 0. The benchmark inversion that shaped the design

The original plan was "use threads — OpenSSL releases the GIL during ECDSA." The benchmark
(`extras/benchmarking/script_verification/RESULTS.md`) proved the **opposite** for Python's
`cryptography` lib:

- **Python threads never help and usually hurt** — `verify()` holds the GIL, so >2 workers
  thrash (32 p2pkh inputs: 11 ms serial → 27 ms at 4 threads → 57 ms at 8).
- **Process pools give real but modest speedup** (~2–3.5×, up to 6× at 255 inputs) — but pay
  pickling/IPC/spawn, and **lose** on the common 1–3-input txs (crossover at **4 inputs**).
- **The Rust arm wins everywhere, by 5–15× over the best process cell, with no crossover** —
  even 1 input is 10.9× — because it's one GIL-released `rayon` batch over `libsecp256k1`
  (several× faster per-signature than OpenSSL's generic ECDSA), with no pickling and no IPC.

So the production default became **`rust`**, with the Python process/thread pools kept behind
the flag as fallbacks.

## 1. What changed

**(A) Interpreter → Rust.** The pure-Python stack machine in `hathor/transaction/scripts/`
(`execute.py`, `opcode.py`, `multi_sig.py`, `construct.py`) is ported **bit-for-bit** into
`htr-rs/crates/htr-lib/src/script/` (`interpreter.rs`, `opcodes.rs`, `matchers.rs`, `crypto.rs`,
`sigops.rs`). The module docstring is explicit (`script/mod.rs:1-7`): *"a consensus-critical,
bit-for-bit port… Python remains the authoritative reference: every accept/reject decision and
every error category must match exactly."*

**(B) Fused batch call.** The bigger structural change is `htr_lib.verify_tx_from_bytes`
(`pipeline/mod.rs:340-524`): one call takes raw tx bytes for a **whole sync batch** and does
*everything Rust can do* — parse (S1), stateless checks (S2), sighash, dependency resolution,
sigops, and full script eval (S3S4) — in **one GIL-released trip** across the FFI boundary,
instead of per-tx-per-stage round-trips into Python.

**(C) Parallel executor.** A new pool `hathor/verification/script_verification_pool.py` packages
each input's evaluation into a self-contained, picklable `ScriptVerificationJob`
(`:154-169`) and runs jobs across one of **five modes** (`:74-80`): `DISABLED` (serial inline),
`THREADS`, `PROCESSES` (spawn), `RUST` (one `htr_lib` rayon batch, GIL released), `SHADOW_RUST`
(Python authoritative, Rust runs alongside and mismatches are logged/counted).

## 2. How it works

### 2a. The script VM (Rust)
`execute_eval` (`interpreter.rs:67-80`) walks the merged opcode stream over a stack of
`StackItem::{Bytes,Int}` — the bytes/int distinction is consensus-visible (Python `assert`s
`isinstance(x, bytes)` in several opcodes). A script is valid **iff exactly one item remains and
it is the integer `1`**. Opcode parsing (`opcodes.rs`) and dispatch (`interpreter.rs:85-105`)
mirror Python exactly, including **version gating** (V1-only opcodes simply don't exist under V2)
and the MultiSig **two-pass** evaluation. The P2PKH/MultiSig matchers (`matchers.rs`) even
reproduce a Python regex quirk: `$` without `re.MULTILINE` also matches before a single trailing
`\n` (0x0A) — consensus-visible, replicated at `matchers.rs:8-21`.

### 2b. Crypto — the single highest-risk detail
`crypto::checksig` (`crypto.rs:49-72`) replicates `op_checksig` exactly, with one deliberate
divergence patch: **strict DER parse + unconditional low-S normalization.**

```rust
let Ok(mut sig) = Signature::from_der(signature) else { return Ok(SigCheck::Invalid); };
sig.normalize_s();
```

Why: OpenSSL 3.x parses strict DER but *accepts high-S* values, so `normalize_s()` is the one
systematic fix needed to match Python's accept set. An invalid sig in `OP_CHECKSIG` pushes `0`
(not an error); in `OP_CHECKDATASIG` it raises — hence a `SigCheck::{Valid,Invalid}` enum rather
than a bool. **PoW deliberately stays in Python** (`verify/mod.rs:88-89`): the target is a float
expression and porting libm could cause last-ulp divergence.

### 2c. The fused batch + GIL release + tiered dependency resolution
`verify_tx_from_bytes` (`pipeline/mod.rs:342`): while the GIL is held, snapshot all settings into
a `ScriptConfig` and clone the native RocksDB `Arc` out of the Python ref (the `Arc` is `Send`,
the `PyRef` isn't). Then **release the GIL for the entire computation**:

```rust
let result = py.detach(|| {                       // GIL released
    let pool = script::thread_pool(num_workers);
    pool.install(|| { /* par_iter over parse, stateless, deps, sigops, scripts */ })
});
```

Inputs that spend other txs get their spent outputs via **tiered resolution** (`resolve_deps`,
`:73-119`): **Tier 1** batch bytes (a tx spending another tx *in the same batch* — spend chains
during sync), **Tier 2** caller-supplied bytes (Python cache entries not yet flushed), **Tier 3**
a native parallel RocksDB read through the shared handle (and the fetched hashes are reported back
so Python can pre-warm its object cache). Jobs are then **flattened across all txs** into one
`par_iter` (`:457,507-516`) — because single-input txs dominate, load-balancing across *all
inputs of all txs* keeps the pool saturated better than per-tx parallelism.

### 2d. Python orchestration, the stash, and the 3-phase merge
`RustVerificationService.precompute_stateless_batch` (`rust_verification_service.py:319-429`) is
the conductor: it serializes the batch (preferring the cached `_origin_bytes`), runs the pipeline,
does a **second pass** supplying missing deps for `UNRESOLVED` txs, and **stashes** per-input
script + sigops verdicts keyed by tx hash (`:419-422`). Anything Rust couldn't handle falls back
to the Python object-based stateless batch / Python script jobs.

Later, the *per-tx* serial verification (`transaction_verifier.py:219-324`) keeps its shape but
runs a **3-phase merge** that preserves exact serial error semantics:
- **Phase 1** (input order, main thread): per input do the cheap storage-touching prechecks
  (size, spent-tx fetch, timestamp, conflict) and *record* a script job; the first precheck
  failure/conflict is remembered, not raised.
- **Phase 2:** run the jobs — or, on a **cache hit** (`has_script_results`), skip building jobs
  entirely and `consume_script_results` from the stash (`test_script_precompute.py` asserts
  **zero** `verify_scripts_batch` calls on a hit).
- **Phase 3** (deterministic merge): walk indices in order; **lowest-index failure wins**, and
  for a single input the script error beats the conflict — byte-for-byte identical to the old
  serial loop.

### 2e. The Python parallel backends (fallbacks)
`THREADS`/`PROCESSES` build a warmed `ThreadPoolExecutor` / **spawn**-context
`ProcessPoolExecutor` (never fork — would clone RocksDB/Twisted state), submit one future per job,
and gather **in job order** (`script_verification_pool.py:391-394`). The `RUST` path is instead a
single `htr_lib.verify_scripts_batch(jobs, …, num_workers)` call. Worker count comes from
`--script-verification-workers` (default 4) and sizes the rayon pool **once** (a process-global
`OnceLock` — later values are ignored).

## 3. The theory — why it's faster

1. **GIL release.** OpenSSL ECDSA holds the GIL, so Python threads serialize on it. Rust's
   `py.detach()` lets real OS threads (rayon) run with no GIL, and frees the reactor thread.
2. **Native crypto.** `libsecp256k1` ≫ OpenSSL generic ECDSA per signature.
3. **Batching amortizes the FFI boundary.** The whole sync batch crosses once as raw bytes;
   marshaling + GIL toggling + pool dispatch are paid per *batch*, not per tx.
4. **Embarrassingly parallel.** Each input's eval is a pure function of a few bytes — no shared
   state, no storage, no cross-input dependency → N independent ECDSA checks on N cores.
5. **Amdahl's law.** Verification was the dominant serial term; shrinking it to ~2% raises the
   TPS ceiling and — crucially — means *further* optimizing verification now buys almost nothing.
   That's why the roadmap then pivots to S5 (consensus/storage). Measured: the single fused call
   ≈ **1,559 TPS**, all Rust verification ≈ **4.8 µs/tx**.

## 4. Why it works / where it doesn't

**Consensus criticality.** One script-eval discrepancy = a **chain split**. The guard is a
three-layer net: (1) **error-category mapping** — Rust `ErrorKind`s map to exact Python exception
class *names* (`script/mod.rs:29-71`), so Python re-raises the right type and `consensus.py`
branches identically (this is why the port reproduces quirks like `OP_DATA_STREQUAL` raising
`UnicodeDecodeError`); (2) **differential testing**
(`hathor_tests/tx/test_rust_script_verification.py`) — corpus + every-truncation/byte-flip
mutations + Hypothesis fuzz + a dedicated **signature-acceptance fuzz** that is the empirical
arbiter of the DER/low-S policy; (3) **shadow mode** (`SHADOW_RUST`) — Python stays authoritative
in production while Rust runs alongside and every mismatch is logged. Intended rollout: soak shadow
on testnet, then flip the default.

**Rejection semantics never depend on Rust.** Every fallback (unparseable bytes, unresolved deps,
header-carrying vertices, genesis/skip-verification, static-metadata ties) defers to Python, which
remains the single source of truth for *what is rejected and with which error*.

**Where parallelism LOSES — and the gates that prevent it.** Fan-out costs more than it saves for
tiny txs. The `min_inputs` gate (default 4) runs jobs serially inline below threshold so 1–3-input
txs pay no pool overhead. **Exception:** the Rust path skips this gate (one in-process call wins
even at 1 input). Oversubscription risk: sizing workers above physical cores re-creates the
thread-thrash failure mode; default 4 is the benchmark sweet spot, not an auto-core-count.

**Known remaining waste (per the roadmap).** On a script-cache *hit*, Phase 1 still walks all
inputs and re-fetches each spent tx for the prechecks ("job rebuild on cache hit",
bottleneck #10) — the cache short-circuits the expensive *eval* but not yet the precheck plumbing.
Also the DER/low-S policy is "frozen" only by fuzz, not a proof: an OpenSSL change on the Python
side could shift the accept set.

## 5. Gating — how to toggle S3S4 on/off

S3S4 has **two independent axes**, both selected through one CLI flag but exercising distinct code
paths — useful for our `--opt -section-s3s4` analysis:

- **Interpreter axis:** `rust`/`shadow-rust` use the Rust VM; `thread`/`process` use the **Python**
  interpreter. So you can parallelize *without* Rust.
- **Parallelism axis:** `--script-verification-workers 0` → `DISABLED` (serial inline); the
  `min_inputs` per-tx gate; and the verifier-level serial fallback
  (`transaction_verifier.py:177-180`, taken when `script_pool is None / skip_script / not enabled`).

**Switch points:**
- Master switch — `ScriptVerificationMode` (`script_verification_pool.py:74-80`).
- CLI — `--script-verification-executor` (choices `process|thread|rust|shadow-rust`, **default
  `rust`**) + `--script-verification-workers` (**default 4**, 0 = serial) +
  `--x-script-verification-min-inputs` (**default 4**) — `hathor_cli/run_node.py:142-151`,
  `run_node_args.py:71-73`.
- Builder verifier selection — `builder.py:600-621`: if `pool.enabled and pool.is_rust_mode` →
  `RustVerificationService`, else plain `VerificationService`. Config via
  `set_script_verification_config(mode, num_workers, min_inputs)` (`builder.py:889-900`), wired
  from `hathor_cli/builder.py:464-481`.

**To baseline S3S4 entirely:** `--script-verification-executor process` (or `thread`/`disabled`)
→ the builder constructs the pure-Python `VerificationService` and **no Rust verification runs**.
`shadow-rust` is the safe intermediate.

**Key files:** `htr-rs/crates/htr-lib/src/{script,verify,pipeline}/*.rs`;
`hathor/verification/{script_verification_pool,rust_verification_service,verification_service,transaction_verifier}.py`;
`hathor/builder/builder.py`, `hathor_cli/{run_node,run_node_args,builder}.py`; tests
`hathor_tests/tx/test_rust_script_verification.py`, `test_parallel_script_verification.py`,
`hathor_tests/verification/test_script_precompute.py`; design `plans/rust-script-verification.md`,
`plans/parallel-script-verification.md`, `plans/rust-verification-service.md`.
