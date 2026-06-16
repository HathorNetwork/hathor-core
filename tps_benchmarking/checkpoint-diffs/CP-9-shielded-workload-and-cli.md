# Checkpoint CP‑9 — Shielded workload sources + CLI, and the deserialize fix

- **Snapshot A:** end of CP‑8 — shielded base, native crypto, balance fix, parameter overrides. The engine
  could measure *transparent/organic* only; no shielded driver path.
- **Snapshot B:** the engine drives **shielded batches end‑to‑end** through S1–S6. Two new tx types
  (`amount-shielded`, `full-shielded`), the harness enables the feature flag, the CLI exposes the selectors
  and parameter toggles — and a second upstream bug (shielded txs couldn't be parsed from bytes) is fixed.
- **Status:** PASS ✓ — `full-shielded`/`amount-shielded`/`--shielded` all accepted 20/20; `--range-proof-bits`
  measurably moves verify cost; transparent/organic **unchanged** (no regression); O<2 rejected with a clear error.
- **Files changed:** engine — new `workload/shielded.py`; modified `workload/{base,transparent,__init__}.py`,
  `node/harness.py`, `analysis/sweep.py`, `cli.py`. ⚠️ hathorlib — `serialization/adapters/generic_adapter.py`.

---

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  ⚠️  CP-9 ALSO PATCHES HATHORLIB (a second upstream bug fix)  ⚠️                        ║
║                                                                                        ║
║  hathorlib/hathorlib/serialization/adapters/generic_adapter.py                         ║
║                                                                                        ║
║  GenericDeserializerAdapter forwarded every read method EXCEPT replace_remaining, so    ║
║  a tx with a shielded/unshield/mint/melt header could not be deserialized from bytes    ║
║  via create_from_struct -> make_vertex_deserializer().with_max_bytes()  ("this          ║
║  deserializer does not support replace_remaining"). That is the standard storage/p2p     ║
║  parse path, so shielded txs were effectively un-relayable as bytes. One-method fix:     ║
║  forward replace_remaining to the inner deserializer. Full write-up:                     ║
║  bugs-found/bug-shielded-deserialize-replace-remaining.md.                               ║
║                                                                                        ║
║  This is the THIRD core/hathorlib deviation carried on tool/tps-bench-shielded          ║
║  (after CP-7 vertex_exporter.py and CP-8 rangeproof.rs + shielded_tx_output.py).         ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 1. Summary

CP‑9 turns the CP‑7 spike recipe into first‑class workload sources and wires them through the CLI, so the
engine can now produce shielded TPS numbers the same way it does transparent ones. The shielded sources reuse
**everything** from the transparent/organic builder — funding, disjoint UTXOs, the tip‑confirming chain
(so consensus stays O(1) and we isolate the *crypto* cost) — and differ only in (a) a `[shielded]` /
`[full-shielded]` attribute on each payload output, and (b) accounting for the per‑output shielded fee. A second
upstream defect surfaced the moment the driver's **S1** re‑parsed shielded bytes (the byte‑parse path was never
exercised upstream); it's fixed in hathorlib (boxed above).

**Headline numbers** (I=1, O=2, organic chain, 64‑bit proofs): transparent ≈ **305 tx/s** vs full‑shielded
≈ **70 tx/s** — driven almost entirely by **S3S4 (verify): ~1.0 ms → ~11.2 ms (~10×)**, the range‑proof
verification. Two notable findings in §5.

## 2. The "minimal harness" decision (benchmark validity)

The CP‑7 spike enabled shielded with the simulator mining service + simulator vertex verifiers (copied from
the branch's own test). We deliberately **do not** use those here: the simulator verifiers **skip
`verify_pow`** (`hathor/simulator/patches.py`), which would make shielded S3S4/S6 incomparable to transparent.
Confirmed empirically (CP‑9) that the **feature flag alone** suffices — with our normal real `TransactionVerifier`
+ weight‑1 PoW, a shielded tx builds and verifies. So `NodeHarness(shielded=True)` only sets
`ENABLE_SHIELDED_TRANSACTIONS=ENABLED`; shielded and transparent share the identical verifier set, and their
per‑stage costs are directly comparable.

## 3. File‑by‑file

- **`workload/base.py`** — `TxSource` gains a class attr `shielded: bool = False`; shielded sources set it True
  so the CLI/sweep know to stand up the node with the feature flag.
- **`workload/transparent.py`** — `render_dsl` factored to two hooks (transparent defaults preserve byte‑identical
  output, verified): `_fee_per_output()` (0) and `_output_suffix()` (""). `per` is raised to cover the per‑output
  fee, and the output split subtracts `num_outputs * fpo` so the txs stay balanced and exact‑I/O.
- **`workload/shielded.py` (new)** — `_ShieldedTxSource(OrganicTxSource)` with concrete
  `AmountShieldedTxSource` (`amount-shielded`, `[shielded]`, fee `FEE_PER_AMOUNT_SHIELDED_OUTPUT`) and
  `FullShieldedTxSource` (`full-shielded`, `[full-shielded]`, fee `FEE_PER_FULL_SHIELDED_OUTPUT`). Reads the live
  fee from `manager._settings` at build time; rejects O<2 (a shielded tx needs ≥2 shielded outputs —
  `verify_trivial_commitment_protection`).
- **`workload/__init__.py`** — import `shielded` so the types self‑register (kept hathor‑free).
- **`node/harness.py`** — `NodeHarness(..., shielded=False)`; when True, build `TestBuilder(settings)` with
  `ENABLE_SHIELDED_TRANSACTIONS=ENABLED` (same verifiers/PoW otherwise).
- **`analysis/sweep.py`** — pass `shielded=get_txtype(tx_type).shielded` to the per‑point harness.
- **`cli.py`** — `_add_shielded_flags()` adds `--shielded`/`--full-shielded`/`--amount-shielded` (select tx type),
  `--range-proof-bits`, `--max-shielded-outputs`; `_apply_shielded_env()` translates the last two into the env
  vars **before** any hathor/hathorlib import (the caps resolve at import time); `_cmd_run`/sweep pass the
  source's `shielded` flag to the harness.
- **⚠️ `hathorlib/.../adapters/generic_adapter.py`** — forward `replace_remaining` to the inner deserializer.

## 4. Verified

```text
# full-shielded (I1 O2, 64-bit): the crypto cost lands in S3S4
$ run --full-shielded -n 20 -w 5
  accepted 20/20   S1 178.9  S2 60.5  S3S4 11211.4  S5 1091.8  S6 1667.4  TOTAL 14210.0 us
  processing throughput : 70 tx/s

# amount-shielded ~ same (surjection over a trivial domain is cheap; range proof dominates)
$ run --amount-shielded -n 20 -w 5      accepted 20/20  S3S4 11839  -> 67 tx/s
# --shielded is full-shielded
$ run --shielded -n 12 -w 3             [run] full-shielded ...  accepted 12/12
# bit-width toggle measurably moves verify cost
$ run --full-shielded --range-proof-bits 40 -n 20 -w 5   S3S4 8512 -> 84 tx/s   (vs 64-bit 11211 -> 70)
# transparent/organic REGRESSION: unchanged
$ run --tx-type organic -n 30 -w 5      accepted 30/30  S3S4 1039  -> 305 tx/s
# guard: O<2 rejected
$ run --full-shielded -o 1              ValueError: 'full-shielded' needs num_outputs >= 2
```

Run recipe (engine pyproject needs ≥3.11, so use the hathor venv python directly):
```bash
cd tps_benchmarking/benchmarks/engine
VENV=/home/lyzah/.cache/pypoetry/virtualenvs/hathor-4nrGODYv-py3.11/bin/python
PYTHONPATH="$PWD/../../..:$PWD" $VENV -m hathor_tps_bench run --full-shielded -n 20 -w 5
```

## 5. Findings

1. **Shielded verification is ~10× transparent**, and it's almost entirely **S3S4 range‑proof verification**
   (~11 ms for 2 outputs at 64‑bit). Throughput ~70 tx/s vs ~305 transparent. Outputs are the expensive axis —
   the mirror image of transparent, where inputs (signatures) dominated.
2. **The double‑`validate_full` is NOT amplified for shielded.** We expected the heavy crypto to re‑run in S6
   (the 2nd `validate_full`), but S6 (~1.7 ms) ≪ S3S4 (~11 ms): once S3S4 marks the vertex FULL, S6 skips the
   crypto re‑verification. So unlike the transparent finding (S3S4 ≈ S6), shielded pays the range‑proof cost
   **once**. (Worth confirming with a dedicated probe in CP‑10.)
   > **CP‑10 refinement:** the probe shows this is precise only for the *dominant* cost. `verify_basic`
   > (range proofs) is cached after S3S4 and not re‑run in S6, but `verify` (surjection proofs + balance)
   > **does** re‑run in S6 — it's just cheap here because the surjection domain is trivial. See CP‑10 §1.
3. **The bit‑width toggle works as a clean cost axis**: 40‑bit → S3S4 8.5 ms / 84 tx/s; 64‑bit → 11.2 ms /
   70 tx/s. amount‑ vs full‑shielded verify cost is ~equal here (trivial single‑token surjection domain).

## 6. Next

- **CP‑10 — measure + findings**: proper shielded‑vs‑transparent sweeps (proof size & verify cost vs
  `--range-proof-bits`; per‑tx cost vs #shielded outputs via `--max-shielded-outputs`), confirm the S6‑not‑amplified
  result with a stage probe, and fold the shielded numbers into the RFC/report.
- **Phase B (CP‑11+)** — segment grammar: mixed (superposition) + `--mult-batches` for tx‑type changes
  mid‑batch (TPS‑over‑time as composition shifts).
