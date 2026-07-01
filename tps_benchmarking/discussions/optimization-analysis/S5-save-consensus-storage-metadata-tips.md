# S5 — Save + Consensus: Rust storage, binary metadata, and the mempool-tips fix

> **What S5 is:** once a tx is verified, write it to RocksDB and run consensus (DAG update,
> void/conflict resolution, mempool-tips maintenance). In our Phase-1 study this is where we
> found the real bottleneck: **S5 consensus dominated by `mempool_tips.update` being O(tip
> count)**. The PR's profiling agrees — `update_critical_indexes` (≈ `mempool_tips.update`) is
> **48% of consensus time**.
>
> **Bottom line up front:** after verification was driven to ~2% (S3S4), **S5 is where the big
> later gains came from.** Four distinct optimizations live here: (1) **Rust-owned RocksDB**,
> (2) **binary metadata serde** (replacing JSON), (3) the **mempool-tips incremental update +
> spender-first short-circuit + `is_new` hint** — the direct fix to the bottleneck we
> independently identified — and (4) **write reduction** (save-dedup, static-metadata skip,
> one WriteBatch per flush). Citations are to the PR clone at `optimized-ref/`.

---

## 1. Rust-owned RocksDB (through a python-rocksdb-shaped shim)

**What changed:** Python no longer opens RocksDB. It constructs a Rust handle
`htr_lib.RocksDb(db_path, cache_capacity)` and wraps it in a python-rocksdb look-alike facade,
so the ~16 existing consumers only swap `import rocksdb` → `from hathor.storage import
rocksdb_compat as rocksdb` and change nothing else (`hathor/storage/rocksdb_storage.py:51-52`,
`storage/mod.rs:63-68`).

**How it works:** the Rust pyclass owns the handle behind a `Mutex`; every CF is plain bytewise
KV (no comparators/merge/snapshots); CF handles are resolved **by name per call** so Python never
holds raw pointers across FFI. Reads/writes release the GIL (`py.detach`), and iterators are
**chunked** (`next_chunk(n)`, default 256) so a scan crosses the FFI boundary once per 256 items,
not once per item.

**The real point — a native read path.** The win is *not* Python-side speed (a PyO3 `get` costs
about the same as python-rocksdb's C binding, and 97% of reads are LRU hits anyway). It's that the
**batch verifier shares the same primary `Arc<Db>` handle** (`storage/mod.rs:80-85`) and reads
spent-output bytes natively — no GIL, no Python round-trip per dependency (this is what powers
S3S4's Tier-3 dependency resolution). Sharing the *primary* (not a secondary instance) means no
staleness: a miss is genuinely "not in the DB."

## 2. Binary metadata serde (replacing JSON)

**What changed:** vertex metadata moved from JSON to a canonical **binary format defined in Rust**,
for both **static** (write-once) and **mutable** metadata (`transaction_metadata.py:347-409`,
`static_metadata.py:54-96`, `metadata/mod.rs`, `static_meta/mod.rs`). The old JSON path is kept
but only for non-storage uses (REST output, `clone()`, the legacy children-migration reader).

**The layouts:**
- **Static** (`static_meta/mod.rs`): `version`, `kind`, then fixed fields — a tx record is exactly
  **42 bytes** (`min_height u64` + `closest_ancestor_block [32]`).
- **Mutable** (`metadata/mod.rs`): a `version` byte, a **flags bitfield** marking which optional
  fields are present, then hot fields as flat binary with **32-byte hashes stored raw** (no hex).
  The rare nano `nc_calls` keeps JSON embedded as a length-prefixed blob — *binary where it
  matters, JSON where it doesn't*.

**Why binary beats JSON (measured):** on a heavy 8-spender record, JSON encode 8.97 µs → binary
1.89 µs (**4.7×**); size 905 B → 337 B (**2.7×**). Crucially **6.4 µs of the 8.97 µs is
dict-building** — hex-encoding 32-byte hashes to 64-char strings and building string-keyed dicts —
so *orjson wouldn't have helped*; you must go to binary. Raw hashes + positional fields kill both
costs. Smaller records also mean less write-amplification on disk.

**Version byte + fresh-DB policy (operational caveat!):** both formats start at `FORMAT_VERSION =
1` and reject any other version. There is **no migration from JSON** and the bundled librocksdb
10.x writes SST footers the old python-rocksdb can't read — so this build **cannot** open an
existing data dir; operators must **re-sync from scratch**. A one-way door, accepted because it's
once per node.

**Field reclassification (partly staged):** the design moves write-once fields (block `score`,
`feature_states`, `nc_block_root_id`) into the static record. **Finding:** the static format *has
the slots* but `feature_states` is still set to `{}` with a "populated in a future PR" comment —
so in *this* PR the format is ready but the actual move isn't fully wired; the field still lives in
mutable metadata for now.

## 3. The mempool-tips fix (the bottleneck we independently found)

**Old:** `update` iterated **all current tips** and re-evaluated each — O(current tip count) per
added tx. Under load the tip set grows with the mempool, making the pass quadratic. Inside the
per-tip check, `_is_tip` scanned **children first** via `tx.get_children()`, which opens a RocksDB
**iterator over the children CF** (`any_non_voided` alone = 22% of consensus).

**New — three layered changes** (`mempool_tips_index.py:134-207`):

1. **Incremental `update` (O(dependencies), not O(tip count)).** Tip-ness depends only on a tx's
   own state and its children/spenders; any tx whose children/spenders changed is *already* in the
   affected set consensus iterates over. So per call you only re-evaluate `tx` and its direct
   dependencies (`get_all_dependencies` = parents + input tx_ids), bounded by the tx's own edges —
   never the whole tip set.

2. **Spender-first short-circuit.** `_is_tip` is a conjunction, so evaluate the *cheap* clause
   first:
   ```python
   if any_non_voided(tx_storage, chain(*meta.spent_outputs.values())):  # metadata-only, LRU-fast
       return False
   if any_non_voided(tx_storage, tx.get_children()):                    # children-CF scan, only if needed
       return False
   ```
   Spenders come straight from in-memory metadata (cache-fast gets); `get_children()` is the
   expensive FFI iterator scan. In a **spend-chain mempool** (B spends A), A already has a spender
   recorded, so the metadata-only check returns `False` and **the children-CF scan never runs**.

3. **The `is_new` hint.** When consensus connects the *base* vertex, it provably has no children
   and no spenders yet (nothing can reference a tx before it's saved), so its tip-ness collapses to
   its own state — **no dependency loads, no children scan at all** (`mempool_tips_index.py:177-185`,
   threaded from `consensus.py:230` / `vertex_handler.py:281` / `manager.py:205-211`).

**Why counters were NOT shipped (the subtle part).** The *full* fix would store a non-voided
child+spender **counter** per tx, making `_is_tip` an O(1) `counter == 0` check. But the naive
"+1 on add / −1 on remove" protocol has an **update-epoch hazard**: when a dependency registers
*within the same consensus update* as the new tx, its recomputed full count already includes the
new tx — a naive +1 double-counts. So the PR shipped the (semantically trivial) spender-first
short-circuit and left counters open, with an explicit note that they need an **update-epoch
signal** from consensus or **event-sourced** counts.

## 4. Write reduction (save-dedup, static skip, WriteBatch)

Per profiling, a tx caused ~3 `context.save`s and **17 RocksDB puts** — much of it redundant:

- **Save-dedup + one-time flush** (`context.py:78-99`): `context.save` defers into a dict keyed by
  hash (so an 8-input tx saving the same spent tx per input collapses to one), then `flush_saves()`
  writes each affected tx exactly once and flips to write-through. **Ordering hazard:** the flush
  must run **once, before any removal path** (`consensus.py:158-163`) — a deferred save flushed
  after a removal would resurrect a row.
- **Static-metadata skip** (`transaction_storage.py:436-443`): metadata-only saves skip rewriting
  the immutable static record (4.1 → 1 puts/tx).
- **One WriteBatch per flush** (`rocksdb_storage.py:128-145`): all dirty txs go out in one atomic
  batch (one WAL write per flush, not two FFI puts per tx); vertex bytes are written only on the
  first flush after a full save (`pending_tx_bytes`), since bytes are immutable.
- **Reorg-only pre-update gate** (`consensus.py:160-169`): the old code updated tips for all
  affected txs *before* the invalidation pass; that's now gated to the reorg path only — on the
  common path the single end-of-update tips pass suffices, and running both would update every
  affected tx's tips **twice** (a perf-and-correctness bug avoided).

## 5. The theory

- **O(tip-count) → O(edges) → short-circuited → O(1)-for-new.** The whole arc turns a pass that
  grows with the mempool into work proportional to one tx's own edges, then removes the expensive
  FFI scan from the common case, then removes even the dependency loads for the fresh vertex.
- **Incremental beats recomputation;** counters would push it to an O(1) integer compare, at the
  cost of a careful update protocol.
- **Write-amplification is the storage lever.** Every `put` is an FFI call + WAL append; rewriting
  unchanged counters or immutable bytes is pure waste. Binary (smaller), save-dedup, static skip,
  and single-WriteBatch all cut puts/WAL writes.
- **Native shared-handle reads** let the off-thread Rust verifier resolve dependencies without
  paying the GIL or a Python round-trip per read.

## 6. Why it works / where it doesn't

- **Consensus end-state must be byte-identical.** The incremental `update` is justified by the
  affected-set argument; `test_sync_mempool.py` asserts the tip count after sync, and was updated
  because a cloned tx now correctly carries `spent_outputs` (disqualifying it as a tip until
  cleared) — confirming the new path reads spenders from metadata.
- **Binary serde correctness:** Rust round-trip tests (truncation/trailing/wrong-version rejection,
  decode requires exact length) plus a Python **JSON-equivalence differential test**
  (`test_metadata_serde.py`); a corrupt stored record **raises** rather than silently falling back.
- **What stays mutable (not moved to static):** `voided_by`, `conflict_with`, `twins`,
  `accumulated_weight`, `spent_outputs`, `first_block`, `validation` — they *are* the consensus
  state and genuinely change (e.g. `FULL → INVALID` on reorgs).
- **Caveats:** the fresh-DB / no-migration requirement; write-amp on `spent_outputs` growth (the
  whole record is rewritten when a spender is added — a v2 key-split is reserved but deferred
  pending disk-bound measurements an in-memory bench can't see); the full tips-counter design
  remains open.

## 7. Gating — how to toggle the S5 pieces

**Important finding:** the storage and serde swaps are currently **unconditional — no runtime
flag** (the design doc intends a `--storage-backend` flag; the code doesn't implement it). The
backend is effectively **build-time** (which `htr_lib` / `rocksdb_storage.py` is shipped). The
consensus/index pieces, by contrast, are each a **single localized branch** and can be A/B-gated
independently:

| Piece | Stage | Switch point |
|---|---|---|
| Rust RocksDB vs python-rocksdb | S5 | `RocksDBStorage.__init__` (`rocksdb_storage.py:51`) — no flag today |
| Binary vs JSON metadata | S5 | the 4 `to_bytes`/`from_bytes` in `transaction_metadata.py` / `static_metadata.py` — no flag today |
| `_is_tip` spender-first ordering | S5/S6 | reorder the two clauses (`mempool_tips_index.py:148-151`) |
| Incremental vs full-scan `update` | S5/S6 | branch at the top of `update` (`mempool_tips_index.py:154`) |
| `is_new` hint | S5/S6 | force `is_new=False` at the call sites (`consensus.py:230`, `vertex_handler.py:281`, `manager.py:211`) |
| Save-dedup (`flush_saves`) | S5 | branch in `context.save` (`context.py:84`); make `flush_saves` a no-op |
| Static-metadata skip | S5 | gate `if not only_metadata` (`transaction_storage.py:438`) |
| WriteBatch flush + `pending_tx_bytes` | S5 | gate `_flush_to_storage` (`rocksdb_storage.py:128-145`) |
| Reorg-only pre-update gate | S5 | flip the `if reorg_info is not None` guard (`consensus.py:160-169`) |

**Key files:** `htr-rs/crates/htr-lib/src/{storage,metadata,static_meta}/mod.rs`;
`hathor/storage/{rocksdb_storage,rocksdb_compat}.py`;
`hathor/transaction/{transaction_metadata,static_metadata}.py`,
`hathor/transaction/storage/{rocksdb_storage,transaction_storage}.py`;
`hathor/indexes/mempool_tips_index.py`, `hathor/consensus/{consensus,context}.py`;
design `plans/rust-rocksdb-storage.md`, `plans/tps-strategy-serde-metadata-storage.md`,
`plans/tps-bottlenecks-and-roadmap.md`.
