# Checkpoint CP‑11 — Mixed (superposition) transactions

- **Snapshot A:** end of CP‑10 — shielded measured; transparent and shielded are separate whole‑tx types.
- **Snapshot B:** Phase B part 1 — a single transaction can carry **both transparent and shielded inputs and
  outputs**. New `mixed-amount` / `mixed-full` tx types + CLI, an extension to the balance reconciliation for
  shielded *inputs*, and a de‑risk spike. Plus a third upstream limitation found and documented.
- **Status:** PARTIAL ✓ — **`mixed-amount` works at any shape** (incl. the user's example‑1: 7 transparent +
  2 shielded inputs, 13 + 2 outputs → accepted). **`mixed-full` works for ≤1 total input**; multi‑input
  full‑shielded is blocked by a pre‑existing surjection‑domain limitation (bug #3, fix deferred).
- **Files changed:** new `workload/mixed.py`, `spikes/spike_cp11_mixed.py`; modified
  `workload/__init__.py`, `config.py`, `cli.py`, `analysis/sweep.py`; ⚠️ core `hathor/dag_builder/vertex_exporter.py`.

---

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  ⚠️  EXTENDS THE CP-7 CORE PATCH (hathor/dag_builder/vertex_exporter.py)  ⚠️            ║
║                                                                                        ║
║  The balance reconciliation now also tracks the GENERATOR (asset) blinding per         ║
║  shielded output (_shielded_asset_blinding_factors) and passes it when a later tx       ║
║  SPENDS a full-shielded output. Without it, a mixed tx with full-shielded INPUTS        ║
║  failed the balance (their commitments are on a blinded generator; CP-7 passed gbf=0).  ║
║  Same file/method as the CP-7 deviation — re-apply together if upstream rebases.        ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 1. De‑risk first (`spikes/spike_cp11_mixed.py`)

Before building, the open question was whether a mixed tx **verifies** (the upstream unshield matrix builds
mixed shapes but only checks header layout). The spike built **1 transparent + 1 shielded input → 1
transparent + 2 shielded outputs** and drove it through full verification → **accepted**. So the DSL spends a
shielded output via `ssrc.out[k] <<< tx` (a source with only shielded outputs exposes shielded output k at
DSL `out[k]`), and the CP‑7 reconciliation handles the mixed case (for amount‑shielded).

## 2. The mixed builder (`workload/mixed.py`)

`mixed-amount` / `mixed-full` (subclasses of `OneTipTransparentTxSource`) build a tx with a four‑number shape:
`t_i` transparent + `s_i` shielded inputs, `t_o` transparent + `s_o` shielded outputs. Construction:

- transparent input UTXOs from `fund` txs (as in transparent.py);
- shielded input UTXOs from `ssrc` source txs — each a transparent‑in → shielded‑out tx (filler‑funded)
  carrying **only** shielded outputs, so its output k is spendable via `ssrc.out[k]`;
- each target spends a mix and emits `t_o` transparent then `s_o` shielded outputs, value‑balanced.

The pure cases fall out: `s_i=s_o=0` → transparent; `t_i=t_o=0` → fully shielded. The shielded slice is
carried on the source instance (set from config); the transparent slice is the usual `num_inputs/num_outputs`.

## 3. Core change — asset‑blinding reconciliation for shielded inputs

CP‑7 reconciled shielded **outputs** and read shielded **inputs'** *value* blinding, but passed generator
blinding `gbf = 0`. That is correct for amount‑shielded (unblinded HTR generator) but **wrong for
full‑shielded inputs**, whose commitments sit on a *blinded* generator. CP‑11 records the asset (generator)
blinding per shielded output (`_shielded_asset_blinding_factors`) and passes it for spent shielded inputs, so
mixed‑full **balance** now holds. (This exposed the *next* gate — surjection — see §5.)

## 4. Config + CLI

- `config.py` `WorkloadConfig` gains `shielded_inputs` / `shielded_outputs` (transparent slice may now be 0;
  validation switched to **total** inputs/outputs ≥ 1, and `shielded_outputs` must be 0 or ≥ 2).
- `cli.py`: `--mixed-amount` / `--mixed-full` selectors + `--shielded-inputs N` / `--shielded-outputs N`.
  Example‑1: `run --mixed-amount -i 7 -o 13 --shielded-inputs 2 --shielded-outputs 2 -n 5000`.
- `analysis/sweep.py` propagates the shielded slice per point.

## 5. The surjection limitation (bug #3) — why `mixed-full` is input‑limited

A FullShieldedOutput's **surjection proof** is built by the DAGBuilder over a hard‑coded **single‑input
"trivial" domain**, but the verifier derives the domain from **all** inputs. So a full‑shielded tx verifies
only when it has **exactly one input**:

```
full-shielded  I=1 : accepted     full-shielded I=2/I=3 : REJECTED (surjection)
amount-shielded I=3 : accepted     (AMOUNT_ONLY has no surjection proof -> unaffected)
```

This is **pre‑existing** (CP‑9/CP‑10 only used `I=1`, so it was never hit) and orthogonal to the CP‑11 balance
work. Documented in `bugs-found/bug-shielded-surjection-trivial-domain.md`. **Workaround:** use
`amount-shielded`/`mixed-amount` for multi‑input mixed workloads; restrict `mixed-full` to ≤1 input until the
domain‑construction fix lands.

## 6. Verified

```text
mixed-amount  7t+2s in, 13t+2s out   accepted 6/6     # user's example-1 shape
mixed-amount  0t in/out, 2s+2s       accepted 5/5     # pure-shielded via mixed
mixed-full    1 input, 2 shielded out accepted 5/5
regressions: 1-tip-transparent 10/10, full-shielded I=1 5/5, amount-shielded I=3 5/5  (Phase A unaffected)
```

> **Watch‑item:** during bring‑up one mixed run failed the balance once, on the very first build of a
> heavily‑loaded process; it did **not** reproduce in 60 subsequent runs (varied seeds). Treated as a likely
> transient, not a deterministic reconciliation bug — flagged for re‑check under load.

## 7. Next

- **Fix bug #3** (real surjection domain from inputs) to unlock multi‑input `mixed-full` — a focused core fix.
- **CP‑12 — `--mult-batches`**: concatenate segments (each `--n N [-i -o] [--shielded -i -o]`) into one timed
  run to chart TPS‑over‑time as composition shifts. (CP‑11 delivers the per‑segment mixed shape; the
  `--shielded` section‑separator sugar and multi‑segment concatenation are CP‑12.)
