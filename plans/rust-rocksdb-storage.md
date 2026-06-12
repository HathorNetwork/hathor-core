# Rust RocksDB storage layer (bytes-only handle migration)

> **Context.** Next infrastructure step decided after the Phase-3 stateless batching
> (`plans/tps-strategy-serde-metadata-storage.md`): move the **RocksDB handle** to Rust while keeping every
> byte of semantics in Python. Rust owns the single primary DB handle; Python consumers call through a thin
> FFI that returns/accepts raw bytes (exactly what python-rocksdb returns today); Rust consumers — the
> raw-bytes batch-verification pipeline — read the same handle natively, GIL-free, with no Python round
> trip per dependency. This is "storage-to-Rust, stage 0": no serde, no object model change, no DB format
> change.

## Why this design (and not the alternatives)

- **Not a RocksDB secondary instance:** a secondary lags the primary and would miss exactly the
  recently-connected vertices that sync needs most; catch-up is racy. One shared primary handle has no
  staleness: a miss means *genuinely not in the DB*.
- **Not the object-model migration (frozen pyclasses):** that is the right end-state for the vertex cache,
  but it is a far larger, invasive project. The bytes-only handle move is independent of it and unblocks the
  Rust read path now. (See "Sequencing" below.)
- **Python performance is deliberately neutral:** python-rocksdb is already a C binding that copies values
  into fresh `bytes`; a PyO3 call does the same (~100–200 ns FFI + memcpy at tens of ns for vertex-sized
  values, against a ~1–3 µs RocksDB get). Cache hits in Python's LRU layer never reach this code. The win is
  exclusively the Rust-native read path.

### What Rust-native reads enable (the consumer that collects the benefit)

The batch verifier needs only **immutable vertex bytes** — its own and its dependencies'. Verified
boundary (2026-06): parse, PoW, outputs/sigops/scripts, sighash, tx weight and UTXO token sums are pure
functions of vertex bytes (+ the tokens index for token versions); block weight/DAA additionally reads
*static* metadata (parent height, feature states), which is also write-once; the only verifications touching
**mutable** state are `verify_conflict` (spent txs' `first_block`/`voided_by`/`spent_outputs`), reward
lock's best-height read, and everything nano (contract state; OCB blueprints are Python source and stay in
Python permanently). So a bytes-only Rust read path covers the whole Rust-eligible verification surface.

**Miss protocol (required regardless of handle owner):** vertices not yet flushed from Python's cache layer
(`--cache` buffers dirty txs) and in-batch dependencies (saved only at connect) are invisible to any DB
read. Rust-native resolution is therefore tiered: (1) in-batch map built by Rust from the batch's own raw
bytes, (2) shared-handle DB read, (3) report unresolved hashes back to Python, which supplies bytes from its
cache layer or falls back to the per-tx Python path. Misses are exact, never stale.

## Ground truth: the complete op surface (inventoried 2026-06)

`hathor/storage/rocksdb_storage.py` is ~100 lines: open with fixed options, dynamic column families,
`repair_db` on first open, `close()`. **No custom comparators, no merge operators, no prefix extractors, no
snapshots anywhere** — every CF is plain KV under default bytewise ordering. This is what makes the swap
safe: the Rust `rocksdb` crate opening this DB sees identical semantics.

Open options to replicate exactly: `no_compression`, `allow_mmap_writes=True`, `allow_mmap_reads=True`,
`write_buffer_size=80MB`, `max_total_wal_size=3GB`, BlockBasedTableFactory with optional LRU block cache
(`cache_capacity`), open-all-existing-CFs, `repair_db` when the DB does not exist yet.

Operations used, by consumer (from grep over all non-test code):

| consumer | get | put | delete | WriteBatch | iterators | other |
|---|---|---|---|---|---|---|
| `transaction/storage/rocksdb_storage.py` (tx, meta, static-meta CFs) | ✓ | ✓ | ✓ | ✓ (atomic tx+meta saves) | `iterkeys`, `iteritems` | `key_may_exist`, `get_property(total-sst-files-size)`, `column_families` |
| `transaction/vertex_children.py` | ✓ | ✓ | ✓ | — | prefix-style scans via `iterkeys` | — |
| `indexes/rocksdb_utils.py` (base for all RocksDB indexes) | ✓ | ✓ | ✓ | ✓ | `iterkeys`, `iteritems` | `get_column_family`, `create_column_family`, `drop_column_family`, `get_property(estimate-num-keys)` |
| `indexes/rocksdb_height_index.py` | ✓ | ✓ | — | ✓ | `iteritems`+`seek`, `seek_to_last`, `reversed` | — |
| `indexes/rocksdb_timestamp_index.py`, `rocksdb_vertex_timestamp_index.py` | ✓ | ✓ | ✓ | — | `seek`, `seek_to_first/last`, `seek_for_prev`, `reversed` | — |
| `indexes/rocksdb_tx_group_index.py` (address/token groups) | ✓ | ✓ | ✓ | — | `seek`, `seek_for_prev`, `reversed` | — |
| `indexes/rocksdb_tokens_index.py` | ✓ | ✓ | ✓ | ✓ | `iterkeys`, `iteritems` | — |
| `indexes/rocksdb_utxo_index.py`, `rocksdb_mempool_tips_index.py`, `rocksdb_info_index.py` | ✓ | ✓ | ✓ | — | `iterkeys` | — |
| `event/storage/rocksdb_storage.py` | ✓ | ✓ | ✓ | ✓ | `itervalues` | `drop_column_family` (reset) |
| `nanocontracts/storage/backends.py` (trie nodes) | ✓ | ✓ | — | — | `iterkeys` | — |
| `feature_activation/storage/feature_activation_storage.py` | ✓ | ✓ | ✓ | — | — | — |
| `sysctl/storage/manager.py` | — | — | — | — | — | `flush()`, memtable stats via `get_property` |
| `metrics.py` | — | — | — | — | — | per-CF `get_property` |
| migrations (`reset_feature_state_cache.py`, …) | — | — | ✓ | — | — | CF drop/reset |

Iterator semantics to preserve (python-rocksdb): iterators are opened per-CF as keys/items/values views;
support `seek(key)`, `seek_to_first()`, `seek_to_last()`, `seek_for_prev(key)`; `reversed(it)` flips
direction; keys/items yield `(cf_name, key)` tuples in the multi-CF API shape.

## Design

### Rust side (`htr-rs/crates/htr-lib/src/storage/`)

One module exposing pyclasses, all `Send + Sync`, GIL released around every RocksDB call:

- **`RocksDb`** — owns `rocksdb::DB` (multi-CF, single primary). Constructor replicates the open options
  and the `repair_db`-on-create path. Methods (Python surface, bytes in/out):
  - `get(cf: str, key: bytes) -> bytes | None`; `multi_get(cf, keys: list[bytes]) -> list[bytes | None]`
  - `put(cf, key, value)`, `delete(cf, key)`
  - `write(batch: RocksDbWriteBatch)` — atomic, multi-CF
  - `iterator(cf, *, mode, key=None, reverse=False) -> RocksDbIterator` where mode ∈
    {`first`, `last`, `seek`, `seek_for_prev`}
  - `key_may_exist(cf, key) -> bool`
  - `get_property(cf, name: str) -> str | None`
  - `list_cfs() -> list[str]`, `create_cf(name)`, `drop_cf(name)`
  - `flush()`, `close()`
- **`RocksDbWriteBatch`** — `put(cf, key, value)`, `delete(cf, key)`; built attached (cheap), consumed by
  `write`.
- **`RocksDbIterator`** — **chunked**: `next_chunk(n: int) -> list[tuple[bytes, bytes]]` (empty list =
  exhausted). One FFI call per *n* items, not per item — this is the parity requirement for index scans;
  python-rocksdb iterates at C speed today. Python-side thin wrappers reproduce the
  `iterkeys/iteritems/itervalues` + `reversed` API over `next_chunk`.
- **Native API (Rust callers):** the same `DB` is reachable in-process by the verification pipeline
  (`Arc<rocksdb::DB>` shared between the pyclass and future Rust modules) — `get_vertex_bytes(hash)`
  without touching Python. This is the point of the whole exercise.

CF handles are resolved by name per call (cheap hashmap in `rocksdb` crate) so Python never holds raw
pointers across the FFI.

### Python side

`RocksDBStorage` keeps its public interface (`get_db()`, `get_or_create_column_family`, `close`) but
returns a compatibility wrapper backed by `htr_lib` when the flag is on. All ~15 consumers are untouched in
stage 1; consumers can later migrate to the wrapper's native chunked-iterator API where profiling justifies
it. The python-rocksdb dependency is retired once the flag becomes the default.

## Compatibility & risks

1. **librocksdb version one-way door — confirmed empirically, resolved by decision.** The Rust crate
   bundles librocksdb 10.x; once it writes an SST, python-rocksdb fails to open the DB with
   `Corruption: Unknown Footer version`. **Decision (2026-06): no cross-binding file compatibility is
   maintained in either direction — switching backends means a fresh database and a re-sync from scratch.**
   (Pinning `format_version=5` would have made files mutually readable, but carrying that constraint isn't
   worth it for a migration that happens once per node.) The newer binding *can* read python-written DBs;
   that is informational, not a supported path.
2. **Option parity.** mmap flags, write buffer, WAL cap, block cache size must match — they affect
   performance and disk behavior, not correctness, but regressions here would be silent. Pin them in one
   shared constant table and assert them in the differential harness.
3. **Iterator chunking semantics.** A chunked iterator observes a snapshot per `next_chunk` call boundary
   differently than a live C iterator only if writes interleave — hathor's index scans run on the reactor
   thread between writes, same as today, so no behavioral change; documented as a constraint.
4. **`repair_db` quirk.** Today a nonexistent DB is created via `repair_db`; replicate first, improve later
   (deliberately, in its own change).
5. **Atomicity parity.** Every multi-op save that uses `WriteBatch` today must go through
   `RocksDbWriteBatch` — enforced by the wrapper exposing no auto-batching fallback.
6. **Exotic-feature creep.** The safety argument rests on "no comparators/merge/prefix/snapshots". Add a CI
   guard (grep) so a future Python change doesn't silently start using an op the Rust layer doesn't expose.

## Rollout

1. Rust module + Python wrapper behind `--storage-backend rust-rocksdb` (default `python-rocksdb`),
   mirroring the script-verification flag discipline. Switching backends on an existing data dir is
   unsupported (risk #1): the node must start from a fresh database and re-sync.
2. **Differential harness:** run the same operation stream against both backends (fresh temp DBs), compare
   every result including iterator order and property queries; plus the full test suite with the flag on.
3. Benchmark: index-scan parity (chunked iterators), get/put parity, and the real target — batch-verify
   dependency resolution via the native path vs Python-supplied deps.
4. Testnet soak with the flag on; then flip the default; then retire python-rocksdb.

## Sequencing

This slots between the Phase-3 stateless batching (done) and the raw-bytes batch verify:

1. **Raw-bytes batch verify** (parse + sighash + stateless + scripts in one Rust call) can land first with
   tier-1 (in-batch) + tier-2 (Python-supplied) deps — it does not block on this work.
2. **This handle migration** then upgrades the verifier's dep resolution to native reads (tier 2 mostly
   evaporates; the miss protocol stays for cache-layer misses).
3. **Binary metadata format in Rust** (already planned) lands on a handle Rust already owns; static
   metadata — verified immutable, "metadata" in name only — joins the Rust-parseable surface there.
4. **Frozen vertex pyclasses / object-model migration** (the shared-object cache design: data in Rust,
   lazily-boxed per-field PyObject caches, identity semantics preserved) becomes the stage after, with
   mutable `TransactionMetadata` staying Python-owned until consensus itself moves.

## Out of scope

- Any serde/format change (metadata stays JSON; vertex bytes already canonical).
- The vertex object model (`Transaction` stays a pure-Python class in this stage).
- Consensus, nano execution (permanently Python — OCB blueprints are Python source).
- RocksDB secondary instances, checkpoints, backups.
