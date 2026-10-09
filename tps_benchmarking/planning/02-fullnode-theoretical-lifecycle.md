# Full-Node Transaction Lifecycle — Theoretical Study (`hathor-core`)

*(Companion deep-dive to `01-lifecycle-and-resource-study-plan.md`. Scope: the full node only — the
wallet/mining half is deliberately excluded. Subject: a transparent, regular transaction arriving via
`POST /push_tx`. "Theoretical / by-design": this traces the code paths and the work each performs,
threaded with the consumption metrics from the study plan. All references are verified against the
`hathor-core` source.)*

## 0. The subsystems that touch a transaction

| Subsystem | Object / file | Role in the journey |
|-----------|---------------|---------------------|
| HTTP boundary | `PushTxResource` — `transaction/resources/push_tx.py` | Accepts the request, decodes hex, rate-limits |
| Parser | `VertexParser` — `transaction/vertex_parser/` | Bytes → in-memory vertex object |
| Orchestrator | `HathorManager` — `manager.py` | Cheap gate-keeping, then hands off; relays after success |
| State machine | `VertexHandler` — `vertex_handler/vertex_handler.py` | Drives validate → save → consensus → post-consensus |
| Verification | `VerificationService` + verifiers — `verification/` | All correctness checks (structure, PoW, signatures, balance) |
| Consensus | `ConsensusAlgorithm` — `consensus/consensus.py` (+ `transaction_consensus.py`) | DAG placement, voided-by, mempool tips, reorg |
| Storage | `TransactionStorage` / RocksDB — `transaction/storage/` | Persist vertex + metadata; serve reads during verify |
| Indexes | `IndexesManager` — `indexes/manager.py` | mempool_tips (critical) + address/tokens/utxo/timestamp (non-critical) |
| Events | `PubSubManager` — `pubsub.py` | Notifies wallet-index/websocket/metrics subscribers |
| Network | `ConnectionsManager` — `p2p/manager.py` | Relays accepted tx to peers (out of single-node scope) |
| Execution host | **Twisted reactor** (single thread) + `SimpleCPUProfiler` (`profiler/cpu.py`) | Everything below runs synchronously on one thread |

## 1. The journey, stage by stage (verified call graph)

**S0 — Arrival (HTTP).** `PushTxResource.render_POST` → `handle_push_tx()`
(`push_tx.py:69`). Reads the `hex_tx` param. *Cost:* trivial CPU; **net ingress** = tx hex size;
one **socket FD**. Endpoint is rate-limited (global 100 r/s, per-IP 3 r/s burst 10) — bypassed by
hitting the backend `:8080` directly in the benchmark.

**S1 — Deserialize.** `manager.vertex_parser.deserialize(tx_bytes)` (`push_tx.py:72`). Hex→bytes,
struct unpack into a `Transaction`. *Cost:* small CPU; allocates the vertex (~1–5 KB **memory**).

**S2 — Manager gate-keeping.** `HathorManager.push_tx()` (`manager.py:828`) runs the **cheap rejects
before** any heavy work: `transaction_exists` (`:832`), `is_double_spending` (`:838`),
`is_spending_voided_tx` (`:842`), `is_spent_reward_locked` (`:846`), and a standard-script check via
hathorlib (`:853`). Then `propagate_tx()` (`:859`) → `on_new_tx()` (`:872`). *Cost:* a few RocksDB
**reads** (input/parent lookups, cache-served on hit); CPU light.

**S3 — Enter the state machine.** `on_new_tx` → `VertexHandler.on_new_relayed_vertex()`
(`vertex_handler.py:129`). Fetches best block, builds `VerificationParams` (feature flags, reward-lock
policy), → `_old_on_new_vertex()` (`:155`). This method is the spine: **validate → save+consensus →
post-consensus**. It is decorated `@cpu.profiler('on_new_relayed_vertex')` / `('_old_on_new_vertex')`
— so per-tx CPU here is already measurable via `/top`.

**S4 — Full verification.** `_validate_vertex()` (`:185`) → `VerificationService.validate_full()`
(`verification_service.py:64`), which runs `verify_basic` then `verify`. For a regular tx the checks
are (file: `verification_service.py`):
- **basic** `_verify_basic_tx` (`:156`): `verify_parents_basic` (exactly 2, no dup), `verify_weight`
  (PoW weight ≥ required — the `MIN_TX_WEIGHT`/size/amount formula; `=1` in test mode), then
  `verify_without_storage`.
- **full** `_verify_tx` (`:240`, decorated `@cpu.profiler('tx-verify!<hash>')`):
  `verify_without_storage` → `_verify_without_storage_tx` = **`verify_pow`** (single integer compare
  vs target — the node *verifies*, never computes PoW), `verify_number_of_inputs`, `verify_outputs`,
  `verify_output_token_indexes`, `verify_sigops_output`, `verify_tokens`; then `verify_sigops_input`,
  **`verify_inputs`** (checks each input exists **+ validates secp256k1 signature / runs the output
  script** — the CPU-dominant step, scales with #inputs), `verify_version`,
  **`verify_transparent_balance`** (inputs sum == outputs sum per token).
*Cost:* **dominant CPU stage** (signatures + script VM); RocksDB **reads** for every input & parent
(cache-miss = disk); transient **memory** for parent/input objects.

**S5 — Save + consensus.** `_unsafe_save_and_run_consensus()` (`:217`):
1. `vertex.update_initial_metadata()` — links the tx as a child of its parents.
2. `tx_storage.save_transaction()` (`storage/transaction_storage.py:425`) — writes tx + metadata to
   the RocksDB **memtable** (fast ~µs; disk flush deferred/batched). *Cost:* **disk-write** pressure,
   **memory** in write buffer, SST **FDs** over time.
3. `indexes.add_to_non_critical_indexes()` inside `non_critical_code()` — timestamp/sorted indexes.
4. `consensus.unsafe_update(vertex)` (`consensus/consensus.py:126`) → `transaction_algorithm.
   update_consensus()` (`:152`): mark inputs as used, **propagate voided-by** for conflicts, set
   conflict twins, refresh **mempool tips**, handle reorg if the best chain moved. *Cost:* **CPU that
   scales with the affected DAG region** (normally tiny; large on conflict/reorg); metadata **writes**.

**S6 — Post-consensus.** `_post_consensus()` (`:232`): **runs `validate_full` a second time**
(`:247`, with `skip_block_weight_verification=True`) — a by-design redundant verification pass worth
noting for the CPU budget — then `update_critical_indexes` (**mempool_tips** — what miners read to
pick parents), `update_non_critical_indexes` (utxo/address/tokens if enabled), and publishes
`NETWORK_NEW_TX_PROCESSING` → consensus events → `NETWORK_NEW_TX_ACCEPTED` via PubSub, then logs.
*Cost:* second verify ≈ repeats S4 CPU; index **writes**; pubsub fan-out (cheap).

**S7 — Relay + respond.** Back in `on_new_tx`, if accepted and `propagate_to_peers`,
`connections.send_tx_to_peers()` (`manager.py:891`) broadcasts (**net egress**; single-node = no-op).
`handle_push_tx` returns `{success, tx}` — **acceptance** is now confirmed to the client. The tx lives
as an **unconfirmed mempool tip** (`metadata.first_block is None`).

**S8 — Confirmation (asynchronous, decoupled).** Later, a **block** (mined by the node's
`pow_thread_pool` / `mining/cpu_mining_service.py`, or received from a peer) runs block consensus and
sets `metadata.first_block` on every reachable mempool tx → the tx is **processed/confirmed**. Gated
by block cadence (`AVG_TIME_BETWEEN_BLOCKS`), not by acceptance throughput.

## 2. Execution model — the master constraint

Stages S1–S7 execute **synchronously on the single Twisted reactor thread** (`vertex_handler.py`
imports the reactor; no work is offloaded). The `pow_thread_pool` exists solely for **block** mining.
Therefore, by design:
- **Per-tx latency** = serial sum of S1…S7 on one core.
- **Acceptance throughput ≈ 1 / (mean reactor-time per tx)** — a single CPU core's per-tx cost is the
  ceiling; adding cores does **not** raise single-node acceptance TPS without architectural change.
- The **dominant terms** are S4 `verify_inputs` (secp256k1 per input) and S6's **second**
  `validate_full`; secondary are S5 consensus set-ops and RocksDB read-misses during verify.

> **Two serialization points, one `1/latency` law.** This document covers the *node-side* serial
> bottleneck (the single reactor thread). There is a second, *emission-side* one outside this doc's
> scope: the headless wallet's **per-wallet send lock** (`lockTypes.SEND_TX`, `src/lock.js`), which is
> a *necessary* design choice — it prevents two concurrent sends from selecting the same UTXO and
> producing conflicting double-spends — and which serializes a single wallet to **`1 / pipeline
> latency`**. It is why the folder-2 benchmark bypasses the wallet and pushes pre-built txs straight
> to `push_tx`. See `01-lifecycle-and-resource-study-plan.md`, Part I.A.

## 3. Consumption metrics, mapped onto the journey

| Stage | CPU (proc time) | Memory | Disk I/O | Net | FDs | Weight/PoW | Built-in measure |
|-------|:---:|:---:|:---:|:---:|:---:|:---:|---|
| S0 receive | low | – | – | ingress | socket | – | rate-limit counters |
| S1 deser | low | vertex alloc | – | – | – | – | py-spy |
| S2 gate | low | – | reads | – | – | – | py-spy |
| S4 **verify** | **high** (sigs) | parents | reads (miss→disk) | – | – | verifies PoW only | `/top` `tx-verify!<hash>` |
| S5 save+consensus | med (reorg→high) | memtable+set | writes | – | SST | – | `/top` `_unsafe_save_and_run_consensus` |
| S6 post (2nd verify) | **high (redundant)** | index | writes | – | – | – | `/top` `_old_on_new_vertex` − inner |
| S7 relay | low | buffer | – | egress | socket | – | Prometheus per-peer bytes |
| S8 confirm | thread-pool | block | writes | – | – | **block 2^weight** | block metrics |

Intrinsics (per workload, not per stage): **weight** `1.6·log₂(size)+4/(1+100/amount)+4` (≥14; =1 in
test mode), **work = 2^weight**, **size** ≈150–350 B for 1-in/1-out, **energy** (analytical) =
CPU_s×TDP×util (node) + work×J/hash (mining model).

## 4. By-design candidate bottlenecks (theoretical — to confirm empirically)

1. **Single-threaded reactor** — the structural ceiling on single-node acceptance TPS.
2. **`verify_inputs` signatures** — secp256k1 per input; scales with #inputs.
3. **Double `validate_full`** (S4 then S6) — verification CPU is paid ~twice per accepted tx.
4. **Consensus voided-by / reorg** — cheap in the happy path, can spike with conflicts/reorgs.
5. **RocksDB read-miss during verify** vs. deferred writes — reads are on the critical path; writes
   are batched (memtable) so disk shows up as periodic flush/compaction spikes (watch FDs + I/O).
6. **Unbounded mempool** — no hard count limit; memory grows until blocks confirm (S8).
