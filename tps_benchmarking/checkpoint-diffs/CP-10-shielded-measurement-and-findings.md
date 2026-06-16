# Checkpoint CP‑10 — Shielded measurement + findings

- **Snapshot A:** end of CP‑9 — the engine can drive shielded batches; one quick run suggested shielded
  verify ≈ 10× transparent and that S6 wasn't amplified.
- **Snapshot B:** a reproducible shielded measurement matrix (transparent vs shielded; bit‑width sweep;
  output‑count sweep), a per‑stage **crypto‑call probe** that pins down exactly what runs where, and the
  findings folded into the report.
- **Status:** PASS ✓ — all rows accepted; clean monotonic trends; the S6 question settled precisely.
- **Files changed:** measurement‑only (no core/crate/hathorlib changes): new
  `spikes/spike_cp10_verify_count.py`, `scripts/shielded_experiments.py`,
  generated `docs/shielded-results.md`, and a report addendum.

---

## 1. The crypto‑call probe (settles the S6 question)

`spikes/spike_cp10_verify_count.py` monkeypatches the shielded‑crypto verify functions (imported
function‑level inside the verifier, so the patch is seen per call) and drives one full‑shielded tx
(O=2) stage‑by‑stage, counting calls:

| stage | `verify_range_proof` | `verify_surjection_proof` | `verify_balance` | `validate_commitment`/`_generator` |
|-------|:---:|:---:|:---:|:---:|
| **S3S4** (`validate_full` #1) | **2** | 2 | 1 | 2 / 2 |
| S5 (save+consensus) | – | – | – | – |
| **S6** (`validate_full` #2) | **0** | **2** | **1** | – |

**Refined finding (sharper than CP‑9):** the double‑`validate_full` is **partially** re‑run, split along the
basic/full boundary:

- **`verify_basic`** (range proofs + commitment/generator validation) runs **once** — it's cached after
  S3S4, so S6 does **not** re‑verify range proofs (the dominant cost). This is why S6 ≪ S3S4.
- **`verify`** (the storage‑bound checks — **surjection proofs + the homomorphic balance**) is **not**
  cached and **re‑runs in S6**.

So range‑proof cost is paid once; surjection+balance are paid twice. With the builder's **trivial
single‑token surjection domain** (I‑independent), surjection is cheap, so the S6 re‑run is small here — but
a full‑shielded tx with a large surjection domain would make S6 grow. (CP‑9's "S6 skips the crypto
re‑verification" was right about the *dominant* cost but imprecise; this is the exact split.)

## 2. Measurement matrix

`scripts/shielded_experiments.py` builds a fresh funded node per row (K=30 measured + W=5 warm‑up),
1-tip-transparent chain (tips≈1, so consensus is O(1) and we isolate the shielded *crypto* cost). Full tables in
`docs/shielded-results.md`. Headlines:

**Transparent vs shielded (I1 O2, 64‑bit), same session:**

| workload | TPS | S3S4 µs | total µs | size B |
|---|---|---|---|---|
| 1-tip-transparent | 177 | 1 807 | 5 643 | 291 |
| amount‑shielded | 35 | 21 714 | 28 272 | 10 570 |
| full‑shielded | 36 | 21 386 | 27 812 | 10 772 |

→ shielded ≈ **5× lower TPS**, **~12× heavier S3S4 verify**, **~36× larger** on the wire. amount ≈ full
(trivial surjection domain). **Outputs are the expensive axis** — the mirror of transparent (inputs/sigs).

**Range‑proof bit‑width (full‑shielded I1 O2):** 40‑bit → S3S4 13.0 ms / 7.1 KB; 52‑bit → 17.6 ms / 9.0 KB;
64‑bit → 19.2 ms / 10.8 KB. Cost and size rise monotonically with the bit‑width (the benchmark sweep axis).

**Shielded output count (full‑shielded I1, 64‑bit):** O2 → S3S4 18 ms / 43 tps; O4 → 31 ms / 27 tps;
O8 → 67 ms / 14 tps. **S3S4 scales ~linearly with #shielded outputs** (one range proof each), size ≈ +5.3 KB
per output, TPS roughly halves as O doubles.

> **Measurement caveat.** These rows ran back‑to‑back on a loaded single machine, so absolute TPS is noisier
> than the Phase‑1 ~215 baseline (e.g. 1-tip-transparent reads 177 here). The **ratios and per‑stage scaling** —
> measured in the same session, fresh node per row — are the result; absolute numbers are indicative.

## 3. What this confirms / adds

- The shielded crypto cost is now **measured**, not hypothesized: range‑proof verification dominates and
  scales linearly with shielded‑output count; bit‑width is a clean cost/size dial (40 vs 64).
- The double‑`validate_full` interacts with shielded verification in a **specific** way (§1) — only the
  full‑phase checks re‑run; the expensive basic‑phase range proofs do not.
- Both upstream bugs (balance reconciliation, byte‑deserialize) had to be fixed before *any* of this was
  measurable — see `bugs-found/`.

## 4. Next

- **Phase B (CP‑11+)** — the segment grammar: mixed (transparent+shielded superposition in one tx) and
  `--mult-batches` for tx‑type changes mid‑batch, to chart TPS‑over‑time as composition shifts.
- Optional: a large‑surjection‑domain variant (more realistic full‑shielded) to exercise the twice‑run
  surjection path identified in §1 — currently masked by the builder's trivial domain.
