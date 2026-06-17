# Checkpoint CP‑12 — `--mult-batches` (TPS over time as composition shifts)

- **Snapshot A:** end of CP‑11 — mixed (superposition) transactions in a single shape per run.
- **Snapshot B:** Phase B part 2 — a **sequence of segments** driven as **one continuous timed stream**, so the
  throughput‑over‑time curve shows TPS shifting as the transaction composition changes on the fly.
- **Status:** PASS ✓ (amount mode). A 4‑segment run (the user's example shape) drives 200/200 and reports
  per‑segment TPS over one stream. Full‑shielded segments are limited by bug #3 (use amount mode).
- **Files changed:** new `workload/multibatch.py`; modified `cli.py` (segment parsing + `--mult-batches`
  handler + `main()` argv split). No core/crate changes.

---

## 1. What it does

```
run --mult-batches --n 2000 -i 5 -o 2 \
                   --n 2000 -i 5 -o 2 --amount-shielded -i 1 -o 2 \
                   --n 2000 -i 5 -o 2 --amount-shielded -i 2 -o 2 \
                   --n 2000 --amount-shielded -i 2 -o 2
```

Four 2000‑tx segments — pure transparent → +1 shielded in/2 shielded out → +2 shielded in/out → fully
shielded — run **back‑to‑back in one node, one timed run**. Each `--n` starts a segment; within a segment the
shielded flag (`--shielded`/`--amount-shielded`) is a **section separator** (transparent slice before, shielded
slice after), reusing the CP‑11 mixed shape. The engine reports **per‑segment TPS** and the rolling‑TPS curve
makes the shifts visible over time.

## 2. Construction (`workload/multibatch.py`)

It must be **one DSL** (separate `build_from_str` calls each declare `blockchain genesis …` and collide). So:

- **shared funding pools** sized for the totals across all segments — `fund` txs (transparent UTXOs) and
  `ssrc` txs (shielded UTXOs), all of a uniform value `per` and a uniform shielded mode;
- **per‑segment targets** `s{k}_tx{t}` consuming from those pools with the segment's mixed shape;
- **one continuous organic chain** — every target parents the previous one, across segment boundaries, so
  tips≈1 for the whole run (the curve reflects the composition change, not a consensus artifact).

`build_multibatch` returns the targets in stream order plus the segment start indices; `run_batch` drives them
as one batch (warmup=0, so the whole stream including transitions is measured).

## 3. CLI plumbing

`--mult-batches` is followed by a free‑form segment stream whose tokens (`--n`, `-i`, `-o`, `--shielded`, …)
argparse would mis‑parse (e.g. `--n` is an ambiguous abbreviation of `--num-*`). Fix: **`main()` splits argv at
`--mult-batches`** before argparse, parses the prefix normally, and hands the raw suffix tokens to
`_parse_segments` (which builds the `Segment` list and detects the uniform mode). The parser keeps the flag
only for `--help`.

## 4. Verified

```text
$ run --mult-batches --n 50 -i 5 -o 2  --n 50 -i 5 -o 2 --amount-shielded -i 1 -o 2 \
                     --n 50 -i 5 -o 2 --amount-shielded -i 2 -o 2  --n 50 --amount-shielded -i 2 -o 2
[mult-batches] 4 segments, 200 txs, mode=amount
[result] accepted 200/200
  seg  shape                 n    TPS
  0    t5/2 s0/0            50     54     # pure transparent
  1    t5/2 s1/2            50     28     # + 1 shielded in, 2 shielded out
  2    t5/2 s2/2            50     31     # + 2 shielded in/out
  3    t0/0 s2/2            50     58     # fully shielded (2 in / 2 out)
  overall: 39 tx/s

regressions: list (6 types), normal run 10/10, full single-input run — all unaffected.
guard: mixing --amount-shielded and --full-shielded in one run errors clearly (uniform mode only).
```

Per‑segment TPS varies with composition (noisy absolute values at n=50 on a loaded machine; the **shifts**
are the result). Outputs: `results/multibatch_<mode>_<segs>seg_<txs>tx/` with `per_tx_stages.csv`, the
rolling‑TPS plots (the TPS‑over‑time view), and `summary.md` with the per‑segment table + boundaries.

## 5. Scope / limitations

- **Uniform shielded mode per run** (one shielded UTXO pool). Mixing amount‑ and full‑shielded slices in one
  `--mult-batches` is rejected with a clear error.
- **Full mode is gated by bug #3:** a full‑shielded slice fails surjection whenever the tx has >1 input *or*
  any full‑shielded input (CP‑12 refined bug #3 — the trivial domain also breaks for a single full‑shielded
  input). So multi‑input shielded mult‑batches must use **amount mode** until the bug #3 fix lands. amount
  mode has no surjection proof and works at any shape.
- warmup is 0 (the whole stream is measured); transitions therefore include a small cold‑start at the very
  front of segment 0.

## 6. Next

- **Bug #3 fix** (build the surjection domain from the real inputs — fully specified in
  `bugs-found/bug-shielded-surjection-trivial-domain.md` §4) to unlock full‑shielded mult‑batches and
  multi‑input `mixed-full`.
- Optional: annotate segment boundaries as vertical lines on the rolling‑TPS plot (currently boundaries are in
  `summary.md`); larger‑n runs for smoother curves.
