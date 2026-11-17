# Hathor Transaction Lifecycle & Resource-Consumption Study (Plan)

## Context

Before building any benchmark software, we need a **design-level study of the full lifecycle of a
(transparent) Hathor transaction** — from wallet creation through full-node processing to block
confirmation — and, at each stage, a profile of the **resources it consumes** (process/CPU time,
memory, network bandwidth, mining work, file descriptors, disk I/O, energy, weight). This study is
the foundation for identifying bottlenecks and for deciding *where* and *how* to instrument the
"folder 2" full-node-ingestion benchmark. **Focus: how the full node processes a transaction once it
arrives** (`hathor-core`); the wallet/mining half is mapped at a lighter, design level.

This is a **study/documentation deliverable**, not software. Sources: local `hathor-core` and
`hathor-wallet-headless`, plus external Hathor repos (`hathor-wallet-lib`, `tx-mining-service`, RFCs).
Facts below are file-cited where verified; **[est]** marks order-of-magnitude estimates to confirm by
measurement.

> Companion document: `02-fullnode-theoretical-lifecycle.md` — the boss-review theoretical deep-dive
> of the full-node processing path, with the verified call graph.

---

## Part I — Transaction lifecycle (design-level map)

### A. Creation & emission (wallet + mining-service) — lighter detail
| # | Stage | Work | Where (repo/file) |
|---|-------|------|-------------------|
| C1 | **Template** | Select UTXOs (greedy, sorted), build outputs, pick tokens; determines tx size | `hathor-wallet-headless/src/helpers/tx.helper.js` (`getUtxosToFillTx`, `prepareTxFunds`) → `@hathor/wallet-lib` `SendTransaction` |
| C2 | **Sign** | secp256k1/ECDSA per input; BIP32 HD key derivation | wallet-lib `send-transaction.signTx()` |
| C3 | **Weight + parents** | Compute weight from size+amount; fetch 2 parent tips + tip/timestamp from node | wallet-lib `prepareToSend()`; node `GET /v1a/tips` |
| C4 | **PoW (delegated)** | Wallet **delegates PoW to `tx-mining-service`** over HTTP (submit job, poll). Service finds nonce via connected stratum miners (cpuminer). **Not mined locally.** | wallet-lib `runFromMining()` → `tx-mining-service` (api/manager/protocol) |
| C5 | **Emit** | Serialize signed+mined tx, push to node | node `POST /v1a/push_tx` |

**Serialization necessity — the per-wallet send lock (`lockTypes.SEND_TX`).** The headless wallet
wraps the entire C1→C5 pipeline in an **in-memory per-wallet mutex** (`src/lock.js`), acquired by
`lockSendTx(...)` at the top of every send route (e.g. `controllers/wallet/wallet.controller.js:268`)
and released only after the tx is sent. This serialization is **by design and necessary, not
incidental** — the source states verbatim: *"We don't support sending multiple transactions
concurrently … to prevent a user from sending multiple requests while the first was not finished."*
The underlying reason is **UTXO-selection safety**: two concurrent sends on the same wallet could
select the **same** UTXO as an input before either is committed, producing conflicting
(double-spending) transactions that the full node would reject. The lock guarantees each send observes
a consistent balance/UTXO state.

Properties and consequences:
- **Reject-on-contention, not a queue.** A second concurrent request to the same wallet fails fast
  with `cantSendTxErrorMessage` rather than waiting; a **2-minute timeout** auto-releases the lock as a
  safety net (`DEFAULT_UNLOCK_TIMEOUT`).
- **Per-wallet and in-process.** Different wallets run independently; the lock is local to one
  instance (a multi-instance deployment would need a distributed lock — noted in the source).
- **Throughput impact.** A single wallet is therefore **strictly serial**, so its emission rate is
  bounded by **single-wallet TPS = 1 / (pipeline latency)** — the reciprocal (serial) law: one tx
  must finish before the next begins, so latency directly caps throughput. This is precisely **why the
  full-node ingestion benchmark (folder 2) must bypass the wallet send path** — pre-building and
  pre-signing transactions offline and pushing them straight to the node's `push_tx` — to measure the
  node's true acceptance ceiling rather than the wallet's serial emission rate.

### B. Full-node processing — **the focus** (`hathor-core`, ordered)
Entry: `POST /v1a/push_tx`. All stages run on the **single-threaded Twisted reactor** (the
`pow_thread_pool` is used **only for block mining**, never tx processing).

| # | Stage | Work | Key files |
|---|-------|------|-----------|
| N1 | **Receive + deserialize** | HTTP parse, hex→bytes, struct unpack into a vertex | `hathor/transaction/resources/push_tx.py` (`handle_push_tx`); `…/vertex_parser/_vertex_parser.py` (`deserialize`) |
| N2 | **Manager pre-checks** | already-exists, double-spend, spending-voided, reward-lock, standard-script | `hathor/manager.py` (`push_tx`) |
| N3 | **Verify (basic→full)** | structural/version/outputs/sigops (basic); parents-exist+timestamps, **PoW verify** (single int compare vs target), inputs/scripts/**signatures** (secp256k1), **weight** check, token/balance | `verification/verification_service.py`; `vertex_verifier.py` (`verify_pow`, `verify_parents`); `transaction_verifier.py` (`verify_weight`, inputs/scripts/tokens) |
| N4 | **Save to storage** | Write tx+metadata to RocksDB memtable (deferred to disk); add non-critical indexes | `vertex_handler/vertex_handler.py` (`_unsafe_save_and_run_consensus`); `…/storage/rocksdb_storage.py` (`save_transaction`) |
| N5 | **Consensus update** | Append to DAG, mark inputs used, voided-by propagation, conflict twins, reorg handling, mempool-tips update | `consensus/consensus.py` (`unsafe_update`); `consensus/transaction_consensus.py` |
| N6 | **Index updates** | Critical (mempool_tips) + non-critical (utxo, address, tokens, timestamp) | `indexes/manager.py`; `indexes/mempool_tips_index.py` |
| N7 | **PubSub + log** | Emit `NETWORK_NEW_TX_ACCEPTED` etc.; structured log | `vertex_handler.py` (`_post_consensus`, `_log_new_object`) |
| N8 | **Mempool presence** | Tx now an **unconfirmed mempool tip** (`first_block is None`); selectable as a block parent | `indexes/mempool_tips_index.py`; `transaction/transaction_metadata.py` (`first_block`) |
| N9 | **Relay** | Broadcast to peers (out of scope: single node) | `manager.py` (`on_new_tx`); `p2p/manager.py` (`send_tx_to_peers`) |

`push_tx` **returns once the tx is accepted into the mempool** (response `{success, message, tx}`) —
it does **not** wait for confirmation.

### C. Confirmation (asynchronous; the "processed" metric)
A later **block** confirms all mempool txs reachable from it → sets `metadata.first_block`
(`consensus/block_consensus.py`). Gated by block production (`AVG_TIME_BETWEEN_BLOCKS = 30s` default,
tunable). Block PoW is computed by the node's `pow_thread_pool` (`mining/cpu_mining_service.py`) — the
only "mining" the node does. **Misconception corrected:** the tx is verified, not mined, by the node.

---

## Part II — Per-stage work × resource consumption (what to profile)

Matrix of which consumables matter per node stage (✓ = primary cost to measure; the study fills in
measured numbers). CPU dominators are N3 (signatures) and N5 (consensus set-ops).

| Stage | CPU/proc time | Memory | Net B/W | Disk I/O | FDs | Mining work | Energy |
|-------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| N1 receive/deser | ✓ | small | ✓ (ingress) | – | socket | – | ∝CPU |
| N2 pre-checks | ✓ | – | – | ✓ reads | – | – | ∝CPU |
| N3 **verify** | ✓✓ (secp256k1) | tx+parents | – | ✓ parent reads | – | – | ∝CPU |
| N4 save | ✓ | memtable | – | ✓ memtable→flush | SST | – | ∝CPU+I/O |
| N5 **consensus** | ✓✓ (set ops, reorg) | affected set | – | ✓ meta writes | – | – | ∝CPU |
| N6 indexes | ✓ | index structs | – | ✓ writes | SST | – | ∝CPU+I/O |
| N7 pubsub/log | small | – | – | log | – | – | – |
| N9 relay | small | buffer | ✓ (egress) | – | socket | – | ∝CPU+net |
| block confirm | thread-pool | block | ✓ | ✓ | – | **2^block_weight** | **mining** |

Intrinsic per-tx quantities measured once per workload (not per stage): **weight**, **size (bytes)**,
**mining work = 2^weight**, **#signatures**.

---

## Part III — Intrinsic per-tx quantities (formulas, file-cited)

- **Weight**: `w = 1.6·log₂(size) + 4/(1 + 100/amount) + 4`, then `w = max(w, MIN_TX_WEIGHT=14)`;
  **TEST_MODE → 1.0**. (`hathor/daa/common.py:199`; constants `hathorlib/conf/settings.py`:
  `MIN_TX_WEIGHT=14`, `MIN_TX_WEIGHT_COEFFICIENT=1.6`, `MIN_TX_WEIGHT_K=100`.) A 1-in/1-out tx ≈ **w≈17** [est].
- **Work / mining cost**: `work = floor(0.5 + 2^weight)` expected hash attempts (`hathor/utils/weight.py`).
  → mining time ≈ work / hashrate; **energy ≈ work × J/hash** (J/hash calibrated per miner).
- **Size**: serialized = funds + graph + nonce; 1-in/1-out transparent ≈ **150–350 B** [est];
  `MAX_SERIALIZED_VERTEX_SIZE=48000`, `MAX_NUM_INPUTS/OUTPUTS=255`.
- **Confirmation/throughput**: `AVG_TIME_BETWEEN_BLOCKS=30s`, `MIN_BLOCK_WEIGHT=21`;
  ~48 KB/block ÷ ~325 B/tx ≈ **~147 tx/block** [est] → confirmation TPS ceiling is block-rate-bound.

---

## Part IV — Measurement methodology (per consumable → tool → stage attribution)

**Big finding:** `hathor-core` already ships the hooks we need, so per-stage CPU attribution needs
little-to-no patching:
- **`SimpleCPUProfiler`** (`hathor/profiler/cpu.py`) with `@cpu.profiler(...)` decorators already on
  the processing stages (`vertex_handler.on_new_relayed_vertex`, `_old_on_new_vertex`,
  `_unsafe_save_and_run_consensus`) and on `transaction_verifier` / `daa`; exposed via a **`/top`**
  REST endpoint (`hathor/profiler/resources/cpu_profiler.py`). Enable with the existing `--profiler`
  CLI flag (see `hathor_cli/tx_generator.py`).
- **Prometheus exporter** (`hathor/prometheus.py`, `hathor/metrics.py`): tx/block counts, hash_rate,
  peers, `best_block_height/weight`, per-peer `sent/received_bytes`, `total_sst_files_size`, GC
  metrics. Enable via `--prometheus-write-path` / interval.
- **RocksDB stats** via sysctl (`hathor/sysctl/storage/manager.py`): memtable/WAL sizes, flush.

| Consumable | Tools (no/low code) | Stage attribution |
|-----------|---------------------|-------------------|
| **CPU / proc time** | `--profiler` (`/top`), **py-spy** (sampling flamegraph, zero-code), cProfile/yappi, `perf` | py-spy flamegraph + `/top` map % to N1–N9 functions |
| **Memory** | psutil/`/proc/<pid>/status` (RSS/VmHWM), tracemalloc snapshots, RocksDB block-cache, `docker stats`/cgroup `memory.current` | snapshot at stage boundaries; steady-state via sampler |
| **Net bandwidth** | Prometheus per-peer bytes, `/proc/<pid>/net/dev`, container net stats; first-order = tx_size×rate | N1 ingress, N9 egress |
| **File descriptors** | `/proc/<pid>/fd` count, `lsof` (sockets vs RocksDB SST) | growth ↔ compaction; sockets ↔ load |
| **Disk I/O** | `/proc/<pid>/io` (read/write_bytes), `iostat`, RocksDB statistics | N4/N6 writes, N2/N3 parent reads |
| **Energy** | RAPL via `perf stat -e power/energy-pkg/`, powertop; estimate = CPU_s×TDP×util; mining = work×J/hash | whole-process + mining model |
| **Whole-stack** | `docker stats` / cgroup v2 (`cpu.stat`,`memory.current`,`io.stat`), node-exporter/cAdvisor + Prometheus | background sampler aligned to run clock |

**Instrumentation depth — DECIDED: hybrid.**
1. **Start black-box** (no code changes): enable the built-in `--profiler` (`/top`) + py-spy
   flamegraphs + Prometheus + `/proc`/cgroup sampling. The existing `@cpu.profiler` decorators
   already cover the N1/N3/N4/consensus boundaries, so this alone yields per-stage CPU shares.
2. **Add white-box markers only where black-box is too coarse**: minimal `perf_counter` timing (or
   extra `@cpu.profiler` keys) around the specific N1–N9 sub-steps that flamegraphs can't separate
   (e.g. splitting N3 signature-verify from parent-reads, N5 consensus set-ops from index writes).
   Keep these as a small, clearly-scoped patch on top of hathor-core, not a broad fork.

**Energy — DECIDED: analytical model only** (no RAPL/hardware dependency; WSL/containers often lack
RAPL). Node energy ≈ `CPU_seconds × TDP × util`; mining energy ≈ `work(2^weight) × J/hash`. Reported
as relative figures for the bottleneck picture; a measured-RAPL pass can be added later if wanted.

---

## Part V — Study execution plan (experiments)

Run on the **Docker Compose privnet** (trivial PoW) defined in the build plan. For each experiment,
record the Part II matrix + Part III intrinsics, and produce the lifecycle resource report.

1. **Single-tx micro-profile**: push one tx with `--profiler` + py-spy → flamegraph + `/top` to get
   the per-stage CPU share (N1–N9) and confirm N3/N5 dominate.
2. **Steady-rate sweep (folder 2)**: push at increasing accepted-TPS; sample CPU/mem/FD/IO/net every
   1–10 s; find the knee where the reactor saturates → the **acceptance ceiling**.
3. **Weight sensitivity**: vary tx weight (test-mode=1 vs realistic ≈14–17) to separate verification
   cost from mining cost and show the realism curve.
4. **Confirmation throughput**: drive block production cadence; measure confirmed-TPS and
   confirmation latency vs mempool depth → the **block-bound processing ceiling**.
5. **Input/size scaling**: vary #inputs (signatures) and size to quantify N3 CPU and bandwidth scaling.

Outputs feed the three benchmark folders: micro-profile + weight/size scaling → **folder 3
(stage-latency)**; steady-rate + confirmation → **folder 2 (fullnode-ingestion)**.

---

## Deliverable & open items

**Deliverable:** this markdown study + the companion theoretical deep-dive
(`02-fullnode-theoretical-lifecycle.md`), plus (planned) a one-page lifecycle diagram. No code.

**Decisions locked:** instrumentation = **hybrid** (black-box first, minimal white-box markers where
needed); energy = **analytical model only**.

**Open items to confirm by measurement / source-reading (not blockers):**
- The **[est]** values: 1-in/1-out tx size & weight, tx/block, per-signature CPU.
- Externally-inferred items: exact `tx-mining-service` HTTP contract and node `tips` endpoint
  name/shape (from `hathor-wallet-lib` source).
