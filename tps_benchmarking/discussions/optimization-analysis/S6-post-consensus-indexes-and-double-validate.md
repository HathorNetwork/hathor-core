# S6 — Post-consensus: index maintenance, reactor yield, and the 2nd `validate_full`

> **What S6 is:** after consensus, update the non-critical indexes, fire pubsub events, and (in
> the original code) run `validate_full` a **second** time. In Phase 1 we singled out that
> redundant second `validate_full` as the **top single-thread optimization target (~1.3×)** —
> and this PR removes it. S6 also hosts a few cross-cutting read/index hot-path fixes.
>
> **Bottom line up front:** S6 is small but contains one optimization we explicitly predicted
> (the double-validate removal) plus the **info-index write-on-change** counter fix and the
> **reactor-yield batching** that smooths the block-sync connect loop. Citations are to the PR
> clone at `optimized-ref/`.

---

## 1. Removing the redundant 2nd `validate_full`

**Old:** `_post_consensus` re-ran `validate_full` on the vertex — a full second verification pass
after S3S4 already validated it (our Phase-1 measurements saw S6 ≈ S3S4 for transparent txs
because of this).

**New** (`vertex_handler.py:271-281`): the re-run is replaced by a cheap assertion plus the
critical-index update:
```python
assert vertex.get_metadata().validation.is_fully_connected()
self._update_critical_indexes(vertex, is_new=True)
```
The vertex's validation state is already `FULL` from S3S4, so re-deriving it is pure waste; an
assertion confirms the invariant without recomputing it.

**Why it works:** consensus does not *invalidate* a vertex on the common (non-reorg) connect path,
so its `validation` is still `FULL` when `_post_consensus` runs. The only case where `FULL →
INVALID` happens is a reorg, which is handled on its own path. So the second full pass was
redundant by construction on the hot path. **Note:** the PR's profiling frames this slightly
differently from our Phase-1 finding — it observed that `verify_basic` (range/commitment checks)
is *cached* after S3S4 while `verify` (the full stage) is not, so on the unoptimized path the
re-run was partial, not a full doubling. Either way, the re-run is removed here.

## 2. Info-index write-on-change counters

**Old** (`rocksdb_info_index.py`): the block/tx **count** indexes serialized and `put` their value
on **every** added vertex — profiling found **8.2 of 17.5 puts/tx** were the info index persisting
counters that mostly didn't need re-writing.

**New** (`rocksdb_info_index.py:44-81`): keep an in-memory mirror of what's on disk and skip the
`put` when unchanged:
```python
if self._stored_values.get(key) == value:
    return
self._db.put((self._cf, key), struct.pack('>I', value))
self._stored_values[key] = value
```
Every *real* change still hits RocksDB immediately (crash semantics intact); only no-op rewrites
are eliminated (8.2 → ~2 puts/tx).

## 3. Reactor-yield batching (block-sync connect loop)

**Old** (`vertex_handler.py`): `yield deferLater(self._reactor, 0, ...)` after **every** connected
tx — one asyncio round-trip (~20 µs) per tx.

**New** (`vertex_handler.py:43,101-138`): yield every `CONNECT_YIELD_EVERY = 8` txs:
```python
if connected % self.CONNECT_YIELD_EVERY == 0:
    yield deferLater(self._reactor, 0, lambda: None)
```

**The theory:** `deferLater(0)` hands control back to the Twisted reactor so other I/O isn't
starved during a long connect loop — but each yield is a ~20 µs round-trip. On a loop that's now
cheap per tx (verification batched/off-thread), yielding every tx wastes that overhead. Yielding
every K=8 amortizes the round-trip 8× while still bounding the longest reactor blockage to 8
connects — a tunable **starvation vs throughput** trade-off (`K` is the knob if block-sync latency
regresses).

## 4. `update_critical_indexes(is_new=True)`

Post-consensus index maintenance now passes the `is_new=True` hint into the critical-index update
(`vertex_handler.py:281`), which (via the mempool-tips index — see [S5](./S5-save-consensus-storage-metadata-tips.md))
lets a freshly-connected vertex skip dependency loads and the children-CF scan entirely, since it
provably has no children/spenders yet.

## 5. Why it works / where it doesn't

- **The assertion guards correctness without cost** — if the invariant ever broke (a vertex
  reaching `_post_consensus` not fully connected), it fails loudly rather than silently skipping
  validation.
- **Write-on-change preserves crash semantics** — real changes are still persisted synchronously;
  only redundant identical writes are skipped.
- **Yield batching is a tunable** — too large starves the reactor (other peers/timers wait), too
  small loses the amortization; `CONNECT_YIELD_EVERY = 8` is a constant chosen for the sync
  workload.

## 6. Gating — how to toggle the S6 pieces

| Piece | Switch point |
|---|---|
| Drop 2nd `validate_full` | `vertex_handler.py:271-281` — restore the full re-run vs the assert |
| Info-index write-on-change | gate the skip in `_store_value` (`rocksdb_info_index.py:76-77`) |
| Reactor-yield batching | `CONNECT_YIELD_EVERY` (`vertex_handler.py:43`) — set to 1 for yield-per-tx |
| `is_new` hint (post-consensus) | force `is_new=False` at `vertex_handler.py:281` |
| get_transaction fast path / scope fusion / miss-probe skip | see [S2](./S2-prechecks-read-fastpaths.md) — these read-path fixes also touch S6 |

**Key files:** `hathor/vertex_handler/vertex_handler.py`, `hathor/indexes/rocksdb_info_index.py`;
design `plans/tps-bottlenecks-and-roadmap.md` (items #5, #8; the double-validate redundancy at
§"Known redundancies").
