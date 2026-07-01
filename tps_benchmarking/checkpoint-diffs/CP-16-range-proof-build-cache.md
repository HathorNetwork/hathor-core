# CP-16 — Range-proof build cache (benchmark-only, verification untouched)

## Why

Building a fully-shielded workload at scale (e.g. `capless-full-shielded` minting thousands of
shielded source UTXOs) spends almost all its **construction** wall-time generating Borromean 64-bit
range proofs — the single most expensive shielded primitive. For a *benchmark* the proof *bytes* only
need to be a valid proof of the committed value; they do not need to be unlinkable across outputs.
When many outputs share the same value (all source UTXOs mint value `per`), we can generate the range
proof **once** and reuse it.

This is a **build-time** optimization for the DAG builder only. It does **not** touch verification: the
node still deserializes, re-verifies every range proof, runs consensus, and stores state exactly as
before. The invariant we hold (and validated): *only build time drops; processing/verify throughput is
unchanged.* If verification time also dropped, the cache would be leaking into consensus — it does not.

## What changed — `hathor/dag_builder/vertex_exporter.py`

Gated entirely behind env `HATHOR_BENCH_CACHE_RANGE_PROOFS=1` (off by default; the harness/report
script sets it). Nothing changes for normal builds or for any production path.

1. **`__init__`** — added `self._cache_rp` (reads the env flag once) and `self._rp_cache: dict` (a
   per-build `{key -> proof_bytes}` map). Also lifted `import os` to module scope (it was only
   imported locally inside the shielded method, so `__init__` couldn't read the env var).

2. **PASS 1 blinding assignment** — when caching, non-reconciled shielded outputs get **fixed**
   value-blinding (`0x11…`), asset-blinding (`0x22…`, full-shielded only) and rewind-nonce (`0x33…`)
   instead of `os.urandom(32)`. Same value + fixed blindings ⇒ identical commitment ⇒ identical proof
   ⇒ cache hit. The **last** output of every tx is still reconciled to the balance residual
   (`compute_balancing_blinding_factor`), so it stays unique and is generated fresh.

3. **`_range_proof(key, gen_fn)` helper** — memoizes `gen_fn()` under `key` when caching is on;
   otherwise calls `gen_fn()` directly. Both the full-shielded and amount-shielded `create_range_proof`
   call sites route through it. The key includes `(is_full, amount, value_blinding, asset_blinding,
   nonce, token_uid)` so a reconciled/random output never collides with a cached one.

### The surjection subtlety (why not *all* outputs are cached)

A fully-fixed asset-blinding is unsafe for a full-shielded output whose tx **also spends a
full-shielded input**: the input carries the *same* fixed asset generator, so the surjection
re-blinding difference is **zero**, and secp256k1-zkp refuses to prove it (`failed to prove
surjection`). This only affects the **measured** txs (few), never the **source** minting (transparent-
funded, no full-shielded input — the bulk). So we detect `spends_full_shielded` up front — an input
whose *recorded asset-blinding is non-ZERO* (amount-shielded/transparent inputs record ZERO and use an
unblinded generator, so they never collide) — and fall those outputs back to random blindings. Result:
the bulk source proofs cache; the measured txs stay correct; surjection is always provable.

Amount-shielded outputs have no surjection and no asset-blinding, so they always cache cleanly.

## Validation (A2)

`capless-full-shielded -i 8 -o 2 -n 300 -w 20 --range-proof-bits 64 --opt`:

| | accepted | processing throughput | total wall |
|---|---|---|---|
| caching OFF | 300/300 | 54 tx/s | 53 s |
| caching ON  | 300/300 | 55 tx/s (flat) | 33 s |

- Correctness preserved (300/300 accepted; surjections valid).
- **Processing/verify throughput unchanged** (54→55 tx/s = noise) — the cache never reaches consensus.
- **Build wall dropped** ~47 s → ~27 s (source minting collapses to cached proofs); grows with N.

## Not changed
- No verification / consensus / storage code touched.
- Default builds (flag unset) are byte-for-byte identical to before.
