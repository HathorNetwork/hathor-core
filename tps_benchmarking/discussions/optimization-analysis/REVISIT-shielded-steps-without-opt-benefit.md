# ⚠️ REVISIT — shielded steps that do NOT benefit from the optimization PR (#1729)

**Status:** open note, to fold into the final report + consider as future work.

Two pipeline steps that PR #1729 accelerates for **transparent** txs fall back to the un-optimized
path for **shielded** txs. This matters for interpreting the shielded scenarios (P3–P8): their
per-stage speedup from `--opt` will be smaller than the transparent ladder, and specifically the
S3S4 stage should barely move between `--opt` and `--no-opt s3s4`.

## The two steps

1. **S3S4 — parallel Rust script pool (the significant one).**
   `hathor/verification/transaction_verifier.py`:
   - `:102` — *"Shielded txs always take the serial path."*
   - `:276-279` — inside `_verify_inputs_parallel`, a **shielded spent output** makes the whole tx
     fall back to `_verify_inputs_serial` (the parallel job model assumes transparent outputs).
   So a tx spending any shielded UTXO gets **no** parallel/Rust-script-pool speedup. Since S3S4 is
   ~a third of the transparent per-tx budget, this is the meaningful gap. (Note: the shielded
   *crypto* verification — range proofs, surjection, commitments — runs in the native
   `hathor-ct-crypto` crate regardless; what's missing is the PR's **script-evaluation
   parallelism**, not native crypto.)

2. **S1 — Rust vertex parser (marginal).**
   `hathor/transaction/vertex_parser/_vertex_parser.py:74-82`: the Rust fast path **declines**
   (returns None) for header-carrying vertices — nano/fee/**shielded** — so every shielded vertex
   parses via the authoritative Python parser. Impact is small (~0.78 µs/tx, ~5% of the budget).

## What to revisit / do

- **Report caveat:** state plainly that shielded scenarios' `--opt` gain is bounded — S3S4 (and S1)
  don't apply to shielded — so shielded TPS reflects mostly native-crypto cost + S5/S6, not the full
  4.3× transparent ladder.
- **Confirm empirically in the collected data:** for a shielded workload, `--no-opt s3s4` should be
  ≈ `--opt` (little/no drop), unlike transparent where s3s4 contributes ~33%. Good sanity check to
  add to the run (a shielded P9/P10 analogue), or just read it off P6/P7 stage breakdowns.
- **Future work (optional):** a shielded-aware parallel verify path — extend the parallel job model
  to shielded spent outputs — would restore S3S4's parallelism for confidential txs. Scope unknown;
  the shielded verify touches range-proof/surjection re-verification per input.

See the section write-ups: `S1-deserialize-rust-vertex-parser.md`, `S3S4-verify-rust-and-parallel-scripts.md`.
