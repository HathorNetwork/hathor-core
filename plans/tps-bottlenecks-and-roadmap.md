# TPS after the fused Rust pipeline: profiling data, bottleneck analysis and roadmap

> **Context.** The verification migration arc is complete: `htr_lib.verify_tx_from_bytes` runs parse,
> stateless checks, input-sigops, sighash and full script evaluation as ONE GIL-released Rust call per sync
> batch, with tiered dependency resolution (batch bytes → supplied bytes → native RocksDB reads through the
> shared handle) and `verify_bytes` as the universal bytes→vertex entrypoint. The RocksDB layer is Rust-owned
> (python-rocksdb replaced). This document records the post-migration profiling (real reactor, no simulated
> clock), the bottleneck analysis, the metadata-format design decisions, and the sequenced plan for the next
> TPS gains.

## 1. Ground truth: real-reactor measurements

Benchmark: `tools/cpu_profiling/bench_real_tps.py` — 2,000 spend-chain txs in 40 blocks fed through the
exact p2p entrypoints (`verify_bytes` + `vertex_handler.on_new_block`) on the real reactor (thread pool
live), real RocksDB, tx-storage cache 100k, rust:12.

| configuration | TPS (median of 3) |
|---|---:|
| pure-Python service | ~980 |
| Rust verifiers, no batching | ~1,064 |
| two-call batching (stateless + script pipeline) | ~1,161 |
| **single fused call (`verify_tx_from_bytes`)** | **~1,559** |

(The tx-storage cache matters: with the default `capacity=0` the LRU degenerates into pure eviction churn —
71k popitems for 2k txs — and the same build measured ~1,290. Production nodes run with a cache.)

Serial budget at 1,559 tx/s: **~640 µs/tx**, all on the reactor thread.

## 2. Where the serial 640 µs/tx goes

cProfile on the reactor thread only (the batched Rust work runs on the thread pool, outside it). cProfile
inflates Python-dense code ~2.3× here; shares are the signal. Pipeline = `on_new_block` cumulative 2.761 s.

| stage | share | ≈ real µs/tx |
|---|---:|---:|
| consensus + save (`_unsafe_save_and_run_consensus`) | 45.3% | ~290 |
| — `consensus.unsafe_update` | 34.8% | ~223 |
| `validate_full` (verification orchestration) | 44.9% | ~287 |
| — `verify` (full stage: prechecks, token sums, parents, conflict, reward lock) | 24% | ~155 |
| — `init_static_metadata` (height/min-height/ancestor walks) | 9.7% | ~62 |
| — `verify_basic` (weight/DAA + parents-basic) | 8.2% | ~53 |
| `_post_consensus` (indexes, pubsub) | 8.0% | ~51 |
| reactor/Twisted dispatch (outside pipeline) | — | ~43 |

Inside `consensus.unsafe_update` (0.984 s profiled):

| step | share of consensus | what it does |
|---|---:|---|
| `update_critical_indexes` ×~4/vertex | 48% | almost entirely `mempool_tips.update`: `_is_tip` re-evaluation loads each affected tx's children+spenders (`any_non_voided` alone 22%) |
| `transaction_consensus.update_consensus` | 23% | conflict/void logic (9%) + `mark_inputs_as_used` → `context.save` per input (14%: JSON encode + RocksDB put) |
| `block_consensus.update_consensus` | 15% | ~3 ms/block: confirm-walk over the block's txs, score, best-chain, nano |
| `height.get_height_tip` ×2/update | 5% | |

The consensus *algorithm* (conflict/void core) is ~50 µs/tx; the index maintenance and metadata persistence
around it cost 3–4× more. The cost is per-edge (parents + inputs), and every edge touch is a storage access.

### All Rust verification, for contrast

64 ms wall total for 2,000 txs (~32 µs/tx, **~2% of the pipeline**), of which 19 ms off-thread. Fused-call
internals per tx (batch=50, rayon×12 wall): parse 0.78 µs, sighash splice 0.45 µs, stateless ~0.3 µs,
deps+sigops+scripts 3.7 µs → **4.8 µs/tx for the entire Rust-side verification**. Verification is done as a
bottleneck; 42 of the 64 ms is itself a removable redundancy (below).

### `get_transaction`: 38.7 calls/tx, 97.3% LRU hits

Instrumented tiers: 97.3% LRU-cache hits, ~0% weakref, 2.7% DB loads — and the DB "misses" are **one
guaranteed-miss probe per new vertex** (`_validate_vertex` → `get_metadata()` on a not-yet-stored vertex →
real RocksDB get → `TransactionDoesNotExist` → caught), right after `transaction_exists()` already said no.

Callers per tx: static-metadata walks **10.0** (closest-ancestor 6.0, inherited-min-height 3.0,
my-min-height 1.0), mempool tips **7.9**, parent walks **6.4** (consensus + verify_parents), spent-tx
fetches **4.0**, `get_block` 4.1, confirm-traversal 2.2, reward-lock 1.0 (the *third* fetch of the same
spent txs), misc ~2.5. Per-call overhead on every get: scope check `is_allowed` (~42 µs/tx total), weakref
re-registration (~37 µs/tx), lock lookup; `get_metadata` runs 124×/tx (~34 µs).

### Metadata serde (measured on a heavy 8-spender record)

| codec | encode | decode | size |
|---|---:|---:|---:|
| JSON (current) | 8.97 µs | 9.80 µs | 905 B |
| binary prototype (pure-Python struct) | 1.89 µs (4.7×) | 3.43 µs (2.9×) | 337 B (2.7×) |

Of the 8.97 µs JSON encode, **6.4 µs is dict-building** (hex-encoding 32-byte hashes, string keys) — so
orjson would NOT help much; go straight to binary. Write pattern: ~3 `context.save`/tx (the tx + each spent
tx) and 17 RocksDB puts/tx total; each spent-tx save rewrites the whole record because one list grew by one.

### Known redundancies (measured)

- **`validate_full` runs `verify_without_storage` twice** (inside `verify_basic` and inside `verify` —
  both stages are deliberately self-contained; the streaming-time basic run under conservative params is a
  *separate, intentional* spam filter). The precomputed stash is popped by run #1, so run #2 makes a fresh
  per-vertex FFI call: 2,014 main-thread calls, ~21 µs/tx.
- The weight/DAA formula runs twice per tx (streaming verify_basic + validate_full) and is
  params-independent: ~31 µs/tx duplicated.
- The same spent txs are fetched three times (verify_inputs prechecks, `mark_inputs_as_used`, reward lock).
- `_verify_inputs_parallel` rebuilds job tuples even on a script-cache hit.

## 3. Top-10 bottlenecks (cost on the 640 µs/tx budget)

| # | bottleneck | cost | fix | est. gain | effort |
|---|---|---:|---|---:|---|
| 1 | `get_transaction` mechanics (38/tx: scope check, weakrefs, lock, validation) | ~178 µs | short: fast-path the default scope, weakref-once; long: object model + native reads | ~90 µs / ~160 µs | S / XL |
| 2 | mempool-tips `_is_tip` re-evaluation (overlaps #1) | ~107 µs | non-voided child/spender **counters** maintained incrementally | ~80 µs | M |
| 3 | consensus core walks (void/conflict/confirm) | ~80 µs | only the Rust-consensus end-state | structural | XL |
| 4 | static-metadata creation at validate_full | ~62 µs + 10 gets/tx | compute in the batch precompute (immutable inputs), later in Rust | ~50 µs | M |
| 5 | metadata persistence (3 saves + 17 puts/tx, JSON) | ~35 µs (+disk) | save dedup per update; WriteBatch per block; binary format | ~25 µs | S–M |
| 6 | double weight/DAA check | ~31 µs | cache by hash (params-independent) | ~30 µs | S |
| 7 | redundant 2nd `verify_without_storage` | ~25 µs | don't pop the stash until `discard` | ~25 µs | XS |
| 8 | reactor dispatch per vertex (`deferLater(0)` each tx) | ~43 µs | yield every K txs | ~30 µs | S |
| 9 | `get_metadata` volume (124×/tx) | ~34 µs | cache refs on hot paths; merges into #1 structurally | ~20 µs | S |
| 10 | triple spent-tx fetches + job rebuild on cache hit | ~30 µs | thread resolved refs through; skip rebuild | ~20 µs | S |

No single multiplier remains — verification was the last big rock. The compounding of #1-short, 2, 4–10
(minus overlaps) is ~250–300 µs: **640 → ~350 µs/tx ≈ 2,800–3,000 tx/s (~1.9×)**, matching the original
Phase-3 projection. Beyond that, the remaining ~350 µs is consensus logic + object/storage mechanics, moved
only by the structural end-state (#1-long, #3).

## 4. Metadata format: decisions

1. **Binary format defined and implemented in Rust**, exposed to Python (`metadata_to_bytes`/`from_bytes`)
   and native to the crate. Not for codec speed — a Python struct codec gets the same ~5× (the boundary
   cost dominates both) — but because the format's future readers are Rust (pipeline, indexes, eventual
   consensus), and one canonical implementation fits the differential-testing discipline. Version byte from
   day one; fresh-DB policy (no migrations), as decided for the storage swap.
2. **Static metadata first.** Write-once, fixed-size, zero locking questions, and an immediate native
   consumer: with a Rust-readable static record the fused pipeline can gather reward-lock data (spent block
   heights, min_height) at precompute, leaving only the best-height comparison at connect.
3. **Reclassify write-once fields into the static record** in the same change: block `score` (past is
   immutable), `feature_states` (deterministic from chain position — coordinate with the upstream move
   already in progress), `nc_block_root_id` (set once at connect; read on every on_new_block for params).
   Node-local bookkeeping leaves the consensus record entirely. Not movable (they ARE the mutable state):
   `voided_by`, `conflict_with`, `twins`, `accumulated_weight`, `spent_outputs`, `first_block`,
   `validation` (FULL→INVALID happens on reorgs: consensus.py:401).
4. **Mutable record layout: single key, fixed-offset header + variable tail.** Hot fields (`validation`,
   flags, `first_block`, weight, score offsets) at fixed positions so native readers can peek without full
   decode — reads are already 97% served by the object cache, so key-splitting for reads buys nothing and
   costs a get forever. Reserve a key-suffix byte so `spent_outputs` (the per-spend mutation hotspot) can
   split into its own key(s) — possibly with a RocksDB merge-append — as a v2, decided by write-amp
   measurements on a disk-bound node, which the in-memory bench structurally cannot see.
5. **`validation` as monotonic bitflags + INVALID overlay** (`BASIC_REACHED | FULL_REACHED | CHECKPOINT |
   INVALID`): the reached-levels are genuinely monotonic; INVALID is an independent overlay (today's enum
   has to special-case INVALID into `is_fully_connected()`). Zero performance impact; strictly cleaner
   semantics, adopted at format-definition time.
6. **Sequencing within the metadata work: save-dedup before format** (fewer saves multiplies with cheaper
   saves).

## 5. Recommended roadmap

### Execution status (updated after landing Phases A + B-partial)

Real-reactor benchmark ladder (same workload as §1):

| state | TPS |
|---|---:|
| baseline at the time of this doc | ~1,559 |
| + Phase A (items 1–5 below) | ~1,861 (+19%) |
| + B7 get fast path + B8 save dedup | ~2,259 (+21%) |
| + static-metadata rewrite skip | **~2,485 (+10%; +59% total)** |

Landed: Phase A complete (stash retention, metadata-probe skip, weight cache, yield batching, job-rebuild
skip), B7 (lock-free LRU-hit path without per-hash lock/weakref churn; fused scope validation), B8
(deferred+deduped consensus metadata saves, write-through after flush for the removal paths), plus a
post-B8 profiling find: metadata-only saves were rewriting the immutable static metadata every time
(4.1 puts/tx → 1).

Fresh profile (post-B7/B8) re-ranks the remainder: the top self-time items are now the compat-layer FFI
ops — RocksDB iterator scans (107 ms profiled; 3.9 of the ~8 scans/tx are `any_non_voided` reading the
children CF inside `_is_tip`) and puts (75 ms; **8.2 of 17.5 puts/tx are the info index persisting its
counters on every add**). So the refined next items:

- **B6 (tips counters)**: the concrete target is eliminating the per-`_is_tip` children-CF scan — a
  non-voided child/spender counter (or per-update children memo) saves an iterator round trip per check,
  not just gets.
- **NEW: info-index counter batching** — 8.2 puts/tx for a handful of integers; persist once per consensus
  update (or per block during sync).
- **WriteBatch per block** for the remaining index puts (timestamp index, tips markers).
- B9 (static metadata at precompute) revised down: GIL-bound Python compute gains little off-thread; its
  real value arrives with the Rust static-metadata format (Phase C).

**Phase A — semantics-free quick wins (each independently committable):**
1. Stash not popped until `discard` (#7, XS).
2. Skip the guaranteed-miss metadata probe for new vertices (#part of get path, XS).
3. Weight-check cache by hash (#6, S).
4. Reactor yield every K txs in the connect loop (#8, S, starvation-tunable).
5. Thread resolved spent-tx refs through prechecks → consensus → reward lock; skip job rebuild on cache
   hit (#10, S).

**Phase B — storage/index mechanics:**
6. Mempool-tips non-voided counters (#2, M — the largest single line).
7. `get_transaction` fast path: default-scope shortcut, weakref-once, lock-path slimming (#1-short, S–M).
8. Metadata save dedup + one WriteBatch per block (#5, S–M).
9. Static-metadata computation in the batch precompute (#4, M).

**Phase C — formats (per §4):**
10. Rust binary static metadata + field reclassification + reward-lock data in the pipeline.
11. Rust binary mutable metadata (header layout, validation bitflags).

**Phase D — the next multiplier (structural):**
12. Frozen-pyclass vertex object model (data in Rust, lazily-boxed Python views, identity preserved),
    native metadata reads for indexes/consensus helpers, then the consensus core itself. This is what moves
    the residual ~350 µs; everything before it is preparation that stays useful.

Projection: A+B ≈ 640→~420 µs (~2,400 tx/s); +C ≈ ~350 µs (**~2,900 tx/s**); D is the path beyond.

All of A–C preserve consensus semantics by construction (they change when/whether deterministic work is
recomputed, never what is checked); each lands behind the existing differential-test discipline.
