# S2 — Pre-checks: read fast-paths and stateless checks in Rust

> **What S2 is:** the cheap gate-keeping before full verification — does this vertex already
> exist? is it a double-spend? is it voided? is the reward locked? These checks are dominated
> not by arithmetic but by **`get_transaction` / `get_metadata` calls** (the node makes ~38.7
> `get_transaction` calls/tx, 97.3% LRU hits). So S2's optimizations are mostly about making
> the *read path* cheaper and skipping a guaranteed-miss probe.
>
> **Bottom line up front:** S2 has no single big rewrite; it benefits from (1) a **lock-free
> LRU fast path** on `get_transaction`, (2) **scope-check fusion**, (3) a **guaranteed-miss
> probe skip** for new vertices, and (4) the **stateless checks being folded into the Rust
> fused pipeline** (covered in [S3S4](./S3S4-verify-rust-and-parallel-scripts.md)). These are
> cross-cutting — they also help S3 and S6 — but they live most naturally in the pre-check
> mechanics. Citations are to the PR clone at `optimized-ref/`.

---

## 1. The read-path cost being attacked

Profiling (`plans/tps-bottlenecks-and-roadmap.md:64-74`): **38.7 `get_transaction` calls/tx,
97.3% LRU hits, ~0% weakref, 2.7% DB loads** — and even the DB "misses" are mostly *one guaranteed
miss per new vertex* (probe a not-yet-stored vertex right after `transaction_exists()` already said
no). The per-call overhead on every get — scope check `is_allowed` (~42 µs/tx total), weakref
re-registration (~37 µs/tx), lock lookup — is the actual cost, not the lookup itself. This is
bottleneck #1 in the roadmap (~178 µs of the 640 µs/tx budget).

## 2. The three fast-path changes

**(a) Lock-free LRU-hit path** (`hathor/transaction/storage/rocksdb_storage.py:263-274`): override
`get_transaction` to return immediately on a cache hit, skipping the per-hash lock and weakref
re-registration:
```python
if tx := self.cache_data.cache.get(hash_bytes):
    self.cache_data.cache.move_to_end(hash_bytes, last=True)
    self.cache_data.hit += 1
    self.post_get_validation(tx)
    return tx
return super().get_transaction(hash_bytes)
```
The per-hash lock only dedups concurrent *loads* — a hit never loads, so it's unneeded. And
anything in the cache was weakref-registered when inserted and is kept alive by the cache's strong
ref ("weakref-once"). `dict.get` / `move_to_end` are GIL-atomic, so this is safe even when the
precompute worker threads call it.

**(b) Scope-check fusion** (`hathor/transaction/storage/transaction_storage.py:467-480`): the
common case — default `VALID` scope + `ValidationState.FULL` — is provably equivalent to the slow
path (`FULL` is fully-connected, neither partial nor invalid), so `is_allowed` reduces to `VALID
in scope` and marker-consistency reduces to "partial marker absent." One assert, then return,
skipping `_validate_partial_marker_consistency` + `_validate_transaction_in_scope`.

**(c) Guaranteed-miss probe skip** (`hathor/vertex_handler/vertex_handler.py:221-228`): for a
not-yet-stored vertex, the storage lookup inside `get_metadata` is a guaranteed miss (a wasted
RocksDB read + a caught `TransactionDoesNotExist`). `_validate_vertex` now calls
`get_metadata(use_storage=already_exists)` — building a fresh metadata object directly for new
vertices, exactly what the miss path produced, without the DB round-trip.

## 3. Stateless checks moved into the Rust fused pipeline

The "stateless" portion of pre-checks (the params-independent structural checks) is also computed
natively as part of the S3S4 fused `verify_tx_from_bytes` batch call (`pipeline/mod.rs:404-416`,
`verify/mod.rs`), then stashed and consumed during per-tx verification. See
[S3S4](./S3S4-verify-rust-and-parallel-scripts.md) §2 — the same one GIL-released batch call does
parse (S1) + stateless (S2) + sigops/sighash/scripts (S3S4). PoW deliberately stays in Python
(float target — libm last-ulp divergence risk).

## 4. The theory

These are **constant-factor** wins on an extremely hot path, not algorithmic ones: 38 gets/tx ×
(lock + weakref + scope-check) is real money when 97% of those gets are otherwise trivial cache
hits. Removing per-call ceremony on the hit path, and not issuing a DB read you *know* will miss,
directly shaves the ~178 µs/tx that `get_transaction` mechanics cost. Folding the stateless checks
into the batch call removes per-tx Python↔Rust round-trips.

## 5. Why it works / where it doesn't

- **Lock-free hit path correctness:** safe only because a cache hit never triggers a load (so the
  load-dedup lock is irrelevant) and the cache's strong ref keeps the object alive (so weakref
  re-registration is unnecessary). The GIL-atomicity of `dict` ops is what makes it thread-safe for
  the precompute workers.
- **Scope fusion correctness:** only the *default VALID scope + FULL* case takes the fast path;
  every other scope/validation combination falls through to the unchanged slow path, so no scope
  semantics change.
- **Probe-skip correctness:** `use_storage=already_exists` is exactly the existing branch — for a
  new vertex `already_exists` is `False`, and a fresh metadata is what the old caught-miss path
  produced anyway.
- **Caveat:** these are micro-optimizations whose benefit depends on the cache being warm
  (production nodes run with a large tx-storage cache; the roadmap notes a `capacity=0` cache
  degenerates into eviction churn).

## 6. Gating — how to toggle the S2 pieces

| Piece | Switch point |
|---|---|
| Lock-free LRU fast path | branch at `rocksdb_storage.py:264` → fall through to `super().get_transaction` |
| Scope-check fusion | gate the fast-path block (`transaction_storage.py:471-479`) |
| Miss-probe skip | force `use_storage=True` at `vertex_handler.py:224` |
| Stateless-in-Rust | follows the S3S4 executor flag (`--script-verification-executor`) — see [S3S4](./S3S4-verify-rust-and-parallel-scripts.md) |

**Key files:** `hathor/transaction/storage/{rocksdb_storage,transaction_storage}.py`,
`hathor/vertex_handler/vertex_handler.py`; design `plans/tps-bottlenecks-and-roadmap.md`
(bottlenecks #1, #7, #9).
