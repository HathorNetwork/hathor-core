# Rust parallel verification service (TPS)

> **Relationship to the other plans.** This generalizes `plans/rust-script-verification.md`. That plan moves one
> slice — per-input *script/signature* evaluation — into Rust. This plan moves the **whole storage-free verification
> set** into Rust and runs it **in parallel across many vertices** in the sync pipeline. Build the script verifier
> first (it delivers the Rust crypto + opcode interpreter + the `ScriptVerificationJob`/batch pattern); this plan
> reuses that crate and extends it. `plans/parallel-script-verification.md` is the already-merged Python process-pool
> foundation that established the `ScriptVerificationPool` abstraction and the differential-test discipline.

## Scope (decided)

Target the **pragmatic boundary**: Rust does the CPU-heavy **stateless verification (Tier 1/2) + scripts**; Python
keeps the **cheap storage-dependent checks** (parents, reward-lock, conflict, block DAA) and the **nano/blueprint
execution**. All verification (Tier 1–3) still parallelizes across vertices via the **ordered-commit (OCC) model**
(§D) — the win there is concurrency, not a Rust rewrite of the cheap checks. A fully-Rust verification core (porting a
native storage read path) is **explicitly out of scope** here and only makes sense if the storage layer itself moves
to Rust later (see "Why not 100% Rust?"). Build on `plans/rust-script-verification.md` first.

## Context

The TPS ceiling is set by **how fast the Twisted reactor thread can verify + connect vertices**, most visibly during
sync/IBD. The pipeline today (verified by exploration):

- Sync-v2 streams transactions into `TransactionStreamingClient._queue` (`hathor/p2p/sync_v2/transaction_streaming_client.py:92`) and processes them **one at a time** via `process_queue` → `_process_transaction` → `verify_basic` (line 179), `callLater(0, ...)` between each. Blocks go through `BlockchainStreamingClient` then `VertexHandler.on_new_block` (`hathor/vertex_handler/vertex_handler.py:81`), which `yield deferLater(reactor, 0, ...)` after **each** tx.
- All verification runs **synchronously on the reactor thread, serially per vertex**. The dominant cost is CPU — ECDSA signature checks + script eval + PoW/sigops/structure — i.e. exactly the storage-free work.

So the lever is: **take the storage-free CPU work off the reactor's critical path, do it in Rust (no GIL) in parallel across a batch of incoming vertices**, and leave only the irreducibly-serial core (storage reads, the few stateful checks, consensus, storage writes) on the reactor thread. Combined with `libsecp256k1` (several× faster per verify), this multiplies IBD throughput; real-time TPS benefits too (verification stops being the per-vertex bottleneck).

## What can and cannot move to Rust (honest tiering)

From a full audit of `hathor/verification/*`:

- **Tier 1 — storage-free, parallel across vertices (the bulk of CPU).** This is `verify_without_storage()` + `verify_basic` structural checks: `verify_pow`, `verify_outputs`, `verify_number_of_outputs`, `verify_sigops_output`, `verify_output_token_indexes`, `verify_data`, `verify_no_inputs`, `verify_number_of_inputs`, `verify_tokens`, `verify_parents_basic`, `verify_version*`, `verify_weight (tx)`; the **script/signature** evaluation (`verify_script`, already covered by the script plan); nano-header `verify_nc_signature`/`verify_actions`; on-chain-blueprint `verify_pubkey_is_allowed`/`verify_nc_signature`/AST checks (`_verify_python_script`/`_verify_raw_text`/`_verify_script_restrictions`/`_verify_has_blueprint_attr`); `verify_aux_pow`; `verify_fee_list`; `verify_token_info`. Needs only the vertex bytes/fields + settings constants + feature flags.
- **Tier 2 — pure *given pre-fetched data* (Python fetches a few small values, Rust computes).** `verify_sigops_input` + `verify_inputs` scripts (need spent-output **scripts/values** — already pre-fetched in Phase 1), `verify_transparent_balance`/`verify_minted_tokens` (need the small `token_dict`), `verify_headers` (allowed-header set from features), `verify_height`, `verify_mandatory_signaling` (feature-activation height), `verify_aux_pow` feature flag, `verify_poa` (parent weight/signer). Marshal the small pre-fetched inputs alongside the vertex.
- **Tier 3 — storage/state reads, stay in Python, but still parallelizable (see "Optimistic parallel full verification" below).** `verify_parents` (DAG lookups + timestamp/metadata), `verify_reward_locked` (best-block height + reward-lock metadata), `verify_conflict` (conflict metadata), nano `verify_method_call`/`verify_seqnum` (nano-contract storage + blueprint service), on-chain-blueprint `_verify_blueprint_type` (executes the blueprint code), `verify_checkpoints` (global best block), block `verify_weight`/`verify_reward` DAA (parent-chain context). These **read** committed storage but do **not** write it. Only `consensus.unsafe_update` + `save_transaction` write — and those stay serial.

**Conclusion:** "the entire service" cannot be Rust *today* (nano/blueprint execution is Python; see below), but **~90% of the per-vertex CPU cost (Tier 1 + Tier 2) can**, and that is what bounds TPS. Furthermore, *all* verification (Tier 1–3) can run **concurrently across vertices** under the ordered-commit model below — only the consensus+save core is irreducibly serial.

### Why not 100% Rust? (the real boundary)

"Needs a dependency (another tx/block)" is **not**, by itself, a blocker — the user's intuition is right. The dependency is in storage; the question is *how Rust reads it*:

- **The trap: reading deps via a Python callback re-acquires the GIL and serializes.** If a Rust verifier calls back into Python (`tx.get_spent_tx`, `tx.storage.get_transaction`) for each dependency, every fetch grabs the GIL — you lose the parallelism you went to Rust for. So "Rust reads deps" only pays off if Rust reads **RocksDB natively**, with no Python on the hot path.
- **Native Rust reads require porting the read path:** the vertex wire format *and* the `TransactionMetadata` format (validation state, `voided_by`, `first_block`, `spent_outputs`, height/min_height) must be deserializable in Rust, and a Rust RocksDB handle must read a **consistent snapshot** that doesn't tear against the live Python writer (RocksDB secondary/readonly or a pinned snapshot). Doable, but it's a real storage/serialization/coordination project — and a second consistency surface to keep bug-for-bug identical.
- **The genuine hard blocker is execution, not reads:** nano-contract method verification (`verify_method_call`/`verify_seqnum`) and on-chain-blueprint `_verify_blueprint_type` don't just *read* a dependency — they **run user Python** (the blueprint VM, `exec` of uploaded code). That cannot move to Rust without a Rust nano-contract VM, which is a separate, much larger initiative.
- **Diminishing returns for the rest:** the storage-dependent-but-non-executing checks (`verify_parents`, `verify_reward_locked`, `verify_conflict`, block DAA `verify_weight`/`verify_reward`) are **cheap** (a few metadata reads + comparisons). Porting them to Rust buys little CPU while adding the whole native-storage-binding cost above. Better to leave them in Python and get their cross-vertex parallelism from the ordered-commit model (their RocksDB I/O releases the GIL; their CPU is negligible).

So the end-state boundary is: **Rust does all the CPU-heavy stateless verification + scripts (high value, low risk); Python keeps the cheap storage-dependent checks and the nano/blueprint execution (the irreducible Python island).** A *fully* Rust verification core is possible only as part of moving the **storage layer + data model itself** into Rust (a "Rust core" architecture) — a legitimate long-term direction, tracked separately, with the nano-contract VM as the last Python holdout.

## Architecture

### A. Rust stateless verifier (extends the script-verification crate)
In `htr-rs/crates/htr-lib` (or a sibling `htr-verify` crate), add a `verify_vertices_stateless(batch) -> Vec<VertexVerifyResult>`:
- Each request carries the vertex's structured fields (version, weight, hash, timestamp, parents, outputs, inputs, tokens, headers, nano-header/OCB fields) + Tier-2 pre-fetched data (spent-output scripts/values, `token_dict`, parent height/weight, feature-activation heights) + a `Settings`/`Features` value.
- Internally runs every Tier-1/Tier-2 check for that vertex; the script checks reuse the interpreter from the script plan. `Python::allow_threads` + `rayon::par_iter` over the batch (and over inputs within a vertex).
- Returns per-vertex `Ok | Err{check, reason}`; Python maps `Err` to the same exception **type** the corresponding Python verifier raises (the merge/type matters for consensus, e.g. `consensus.py:551`; the message text is debug-only and may differ).

**Marshalling boundary (design choice):** start by marshalling already-parsed structured fields from Python (fastest to build, reuses Python's parser). Later, for max throughput, move vertex **deserialization** into Rust (pass raw wire bytes) to avoid double-parsing — track as a follow-up, not v1.

### B. Pipeline parallelism (the TPS win)
Insert a **parallel stateless stage** before the serial connect stage, at the sync-v2 buffers:
- **Primary insertion point** — `TransactionStreamingClient`: accumulate the `_queue` into batches of N; run `verify_vertices_stateless` on the whole batch in Rust (off-reactor, GIL released); then feed results into the existing serial `process_queue` which now only does storage fetch + Tier-3 checks + consensus + save. (`transaction_streaming_client.py:129-170`.)
- **Block path** — `VertexHandler.on_new_block` / `_execute_and_prepare_next`: stateless-verify a block's whole tx list in parallel before the serial per-tx connect loop (`vertex_handler.py:81-112`). Mark stateless results on the vertex (a `validation` ≥ BASIC marker) so the serial stage skips re-doing Tier-1/2.
- Keep the storage-dependent connect + `consensus.unsafe_update` + `save_transaction` strictly serial and topologically ordered (unchanged).

**Dependency rules that make this safe:** Tier-1/2 checks read only the vertex itself (and small pre-fetched data) — they are independent across vertices, so a whole batch can be verified in any order/parallel. Intra-block tx dependencies do **not** affect stateless checks (they never look at sibling txs). Only the serial connect stage needs parents/inputs already in storage, which sync already guarantees (blocks before their txs; topological order preserved).

### C. Integration with existing abstraction
Generalize `ScriptVerificationMode`/`ScriptVerificationPool` (`hathor/verification/script_verification_pool.py`) into a verification executor with a `RUST` mode whose batch call is `verify_vertices_stateless`. `VerificationService.verify_basic`/`verify_without_storage` gain a "results already computed by the batch verifier" fast-path so the serial path doesn't recompute. Wire via Builder/CLI exactly like the shipped pool (`--script-verification-executor rust`, plus a `--x-stateless-batch-size`).

### D. Optimistic parallel full verification (ordered commit)

Full verification is a **read-only function of `(vertex, committed storage snapshot)`** — `validate_full` mutates only the vertex's *own* in-memory metadata; it never writes shared storage (writes happen only in `consensus.unsafe_update` + `save_transaction`). And conflict resolution is **not** done at verify time: `verify_conflict` (`transaction_verifier.py:514`) only rejects conflicts with *confirmed* txs and is gated on a mempool-only flag; two new conflicting txs both pass verification and consensus voids one **in order**. Therefore multiple transactions can be **fully** verified simultaneously, provided they are committed to consensus in receive order (the user's invariant). Model:

1. **Parallel verify** (workers): each in-flight vertex is fully verified against a **pinned committed snapshot**. No writes; reads are immutable (saved vertices/output scripts) or stable-within-a-block (best height, confirmed/voided state change only when a *block* connects).
2. **Serial commit** (reactor, strict receive order): for each verified vertex, do a **cheap re-check of the order-sensitive invariants** before `save` + `consensus.unsafe_update` — (a) all dependencies are now connected (else defer/re-verify), (b) no confirmed-conflict appeared since the snapshot. This is OCC validation: the expensive work is parallel/optimistic; the serial tail only re-checks and commits.

Safety caveats the commit stage must enforce: **intra-batch data dependencies** (a tx that spends/parents another still-in-flight tx waits for it to commit, i.e. respect topological order), and **a block connecting mid-batch** invalidates pinned snapshots → bound batches between block connections or re-verify affected vertices. Conflict/double-spend handling is unchanged because it already lives in consensus.

This extends parallelism from Tier-1/2 to the **entire** verification, shrinking the serial reactor core to: snapshot-pin → (parallel verify) → cheap re-check → consensus + storage write.

## Consensus exactness (non-negotiable)

Same discipline as the script plan, generalized to every Tier-1/2 check:
- **Python stays authoritative and default.** Rust opt-in until proven.
- **Differential harness**: for a large corpus of real + generated + fuzzed vertices, assert Rust's per-check accept/reject (and resulting exception *type*) is identical to running the Python verifiers. Cover every Tier-1/2 check, every vertex type (block, tx, token-creation, merge-mined, PoA, nano, OCB), and malformed inputs.
- **Signature/DER acceptance fuzz** (inherited from the script plan) is the highest-risk item.
- **Shadow mode**: run Python (authoritative) + Rust in parallel in production; metric/log/crash-on-mismatch on testnet before Rust becomes authoritative.

## Rollout

1. **Phase 0** — land `plans/rust-script-verification.md` (Rust crypto + opcode interpreter + script batch). Prereq.
2. **Phase 1** — Rust Tier-1 checks (no pre-fetched data) + differential harness; expose `verify_vertices_stateless`; Python fast-path for `verify_without_storage`. No pipeline change yet (call it inline, prove equivalence).
3. **Phase 2** — Rust Tier-2 checks (marshal pre-fetched spent scripts/values, `token_dict`, feature heights).
4. **Phase 3** — pipeline parallelism: batch the sync-v2 `_queue` / block tx-list, run stateless verification in parallel off-reactor; serial connect stage consumes results. Benchmark IBD txs/sec before/after.
5. **Phase 4** — shadow mode on testnet → flip default to `rust`. Keep Python path as fallback.

## Critical files

- Rust: `htr-rs/crates/htr-lib/src/verify/{mod,stateless,outputs,sigops,pow,tokens,headers,ocb_ast}.rs` (+ reuse `script/` from the script plan); `verify_vertices_stateless` pyfunction in `src/lib.rs`; `htr_lib.pyi`; `Cargo.toml` deps (`sha2`, `secp256k1`, `rayon`, …).
- Python verification: `hathor/verification/verification_service.py` (batch fast-path for `verify_basic`/`verify_without_storage`), `hathor/verification/script_verification_pool.py` (generalize to a `RUST` stateless executor), the per-type verifiers (read-only reference for exact semantics).
- Pipeline: `hathor/p2p/sync_v2/transaction_streaming_client.py` (batch the `_queue`), `hathor/p2p/sync_v2/blockchain_streaming_client.py`, `hathor/vertex_handler/vertex_handler.py` (`on_new_block` batch; mark stateless-verified).
- Wiring: `hathor/builder/builder.py`, `hathor/manager.py`, `hathor_cli/{run_node,run_node_args,builder}.py`.
- Tests/bench: `htr-rs/...` cargo tests; `hathor_tests/verification/test_rust_stateless_verification.py` (differential + fuzz, all vertex types); an IBD throughput benchmark (txs/sec) extending `extras/benchmarking/`.

## Verification

1. `cd htr-rs && just all` — Rust unit vectors for every Tier-1/2 check.
2. `uv run pytest hathor_tests/verification/test_rust_stateless_verification.py` — **zero** Python↔Rust mismatches over corpus + fuzz across all vertex types.
3. `uv run pytest hathor_tests/` with the existing suite under `HATHOR_TEST_SCRIPT_VERIFICATION=rust` / stateless-rust enabled.
4. IBD throughput benchmark: sync a fixed block range with stateless verification serial vs parallel-Rust; report txs/sec and reactor-thread CPU time on `validate_full` (use `hathor/profiler.py`).
5. `uv run mypy` + full `uv run pytest -n auto`.
6. Manual: testnet sync with `--script-verification-executor rust` + shadow mode; observe txs/sec, zero mismatches, and that consensus/storage remain the only serial hot spots.
