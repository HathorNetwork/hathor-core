# Checkpoint CP‑7 — Shielded base branch + native crypto + the balance‑reconciliation fix

- **Snapshot A:** end of Phase 1 (CP‑1…CP‑6) — the `hathor_tps_bench` engine on `tool/tps-benchmarking`,
  transparent/organic workloads measured, ~215 tx/s baseline. No shielded support; older hathor‑core base.
- **Snapshot B:** a new branch `tool/tps-bench-shielded` = **`feat/shielded-outputs` + our engine overlaid**,
  with the native confidential‑transactions crypto **compiled**, and a de‑risk spike proving a shielded tx
  **builds and verifies end‑to‑end** — after fixing a real construction bug in the upstream DAGBuilder.
- **Status:** PASS ✓ — `hathor_ct_crypto` round‑trips; amount‑shielded **and** full‑shielded txs build +
  pass `verify_shielded_balance`; the transparent baseline still runs unchanged on the new base.
- **Files changed:** 1 **hathor‑core** file patched (`hathor/dag_builder/vertex_exporter.py`, +92/‑33) ⚠️,
  1 new spike (`spikes/spike_cp7_shielded.py`). No engine modules yet — that is CP‑8.

---

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  ⚠️  THIS CHECKPOINT MODIFIES HATHOR‑CORE — NOT JUST THE BENCHMARK ENGINE  ⚠️          ║
║                                                                                        ║
║  File:   hathor/dag_builder/vertex_exporter.py                                         ║
║  Method: VertexExporter.add_shielded_outputs_header_if_needed                          ║
║  Why:    the upstream DAGBuilder builds shielded‑OUTPUT txs that CANNOT pass            ║
║          verification (it never reconciles the Pedersen value‑blinding factors).       ║
║          Until this is fixed, NO shielded‑output tx can be benchmarked, because the     ║
║          node rejects it with "shielded balance equation does not hold".               ║
║                                                                                        ║
║  Scope:  this is the FIRST time the project edits hathor‑core itself. Every other CP   ║
║          lives entirely under tps_benchmarking/. The patch is carried on our branch    ║
║          `tool/tps-bench-shielded`. It is, in effect, an upstream BUG FIX (their own    ║
║          tests never drive a shielded‑output tx through verification, so they never     ║
║          hit it). IF feat/shielded-outputs is updated upstream, this patch must be      ║
║          re‑applied / rebased. See §3 for the full rationale and §6 for the diff.       ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 1. Summary

CP‑7 moves the project onto a branch that actually has shielded outputs implemented, compiles the
native crypto, and **de‑risks the entire shielded workstream with a single spike** before any engine
code is written. Three things had to be true for shielded benchmarking to be feasible at all:

1. the confidential‑transactions crypto must be **real and runnable** in‑process;
2. we must be able to **construct** valid shielded txs programmatically (reproducibly enough for a corpus);
3. those txs must **pass real verification** so the node accepts them (otherwise there is nothing to time).

(1) and the build path were confirmed quickly. (3) was **not** true out of the box: the branch's DAGBuilder
produces shielded‑output txs that fail the homomorphic balance check. We root‑caused it, fixed it in
hathor‑core (the boxed patch above), and the spike now shows both shielded modes building **and** verifying.
The transparent baseline is unaffected. CP‑8 will turn the spike recipe into a `workload/shielded.py` plugin.

---

## 2. Branch setup (how Snapshot B was assembled)

Our engine (`tps_benchmarking/`) is a **disjoint subtree** — it does not exist on `feat/shielded-outputs`,
and our Phase‑1 branch has none of the ~49 shielded files — so the two combine with zero path conflicts.
The native crate (`hathor-ct-crypto/`) and the `build-shielded-crypto` Makefile target exist **only** on the
shielded branch, and `import hathor` is an **editable install resolving to the in‑place `hathor/` dir** — so
the main checkout itself must be on a shielded base (a side worktree would still import the old hathor). Hence:

```bash
git branch backup/tps-benchmarking-pre-shielded HEAD          # safety net (== origin/tool/tps-benchmarking)
git checkout -b tool/tps-bench-shielded origin/feat/shielded-outputs
git checkout tool/tps-benchmarking -- tps_benchmarking/        # overlay engine (disjoint; restores report PNGs)
git branch --unset-upstream                                    # so a stray push can't hit feat/shielded-outputs
```

Then the crypto:

```bash
make build-shielded-crypto      # -> maturin develop --release --features python  (Rust + secp256k1-zkp)
```

The poetry venv is Python **3.11.0rc1** (the crate needs ≥3.11; the system `python3` is 3.10 and is rejected —
run the engine via the venv interpreter, see §5). Rust toolchain cargo/rustc 1.94. Build time ~14 s.

> **Operational note.** The engine's own `pyproject.toml` requires ≥3.11, so `poetry run` *from the engine dir*
> fails to find an interpreter. Run with the hathor venv python directly and set `PYTHONPATH` to the repo root
> (editable `hathor` resolves via cwd/sys.path, not site‑packages). Exact commands in §5.

---

## 3. The construction bug — discovery, root cause, fix (the heart of CP‑7)

### 3.1 Symptom
The first spike built a `[full-shielded]` tx via the DSL and drove it through the node. It got all the way
through parsing and proof verification (range/surjection proofs **verified**) and then died at the balance step:

```
hathor.exception.InvalidNewTransaction: full validation failed: shielded balance equation does not hold
```

### 3.2 Root cause
`verify_shielded_balance` (`hathor/verification/transaction_verifier.py:915`) checks the homomorphic equation
`sum(C_in) == sum(C_out) + fee*H`. A shielded output's commitment is `C = v*H + r*G`; transparent
inputs/outputs and fees are trivial commitments `v*H` with blinding `r = 0`. For the points to cancel, **two**
conditions must hold:

- **values balance:** `sum(v_in) == sum(v_out) + sum(v_shielded) + fee` — guaranteed by the DAGBuilder filler;
- **blindings cancel:** `sum(r_in) == sum(r_out)` — i.e. for all‑transparent inputs, `sum(r_shielded) == 0`.

The upstream `add_shielded_outputs_header_if_needed` assigned **every** shielded output an independent
`os.urandom(32)` value‑blinding and **never reconciled them**, so `sum(r_shielded)` was an arbitrary non‑zero
scalar and the `G` component never cancelled. The equation could not hold except by astronomically improbable
accident. The branch builds the *opposite* direction correctly (shielded‑in → transparent‑out, via the
`UnshieldBalanceHeader`'s excess scalar), but the **shield direction** (transparent‑in → shielded‑out) was
build‑but‑not‑verifiable.

### 3.3 Why upstream never caught it
**No upstream test drives a shielded‑output tx through `verify_shielded_balance`.**
`test_shielded_dag_builder.py` only *builds and inspects* (asserts output types/sizes). The unshield matrix
test only asserts header layout/serialization, or deliberately tests mutual‑exclusion **rejections** that
short‑circuit *before* the balance crypto. The correct residual‑blinding recipe exists only at the FFI level
in `hathor_tests/tx/test_shielded_audit_equation.py::_shield_in_tx`, which never goes through a `Transaction`.

### 3.4 The fix
Reconcile the **last** shielded output's value blinding instead of randomising it. Concretely, restructure
the method into two passes:

1. **Pass 1** — collect one spec per shielded output (amount, token, script, ephemeral keypair, ECDH nonce,
   `is_full`), assigning a random value‑blinding to each (and a random asset‑blinding for full‑shielded).
2. **Reconcile** — gather the inputs/outputs/fees exactly as the verifier folds them and set
   `last.blinding = compute_balancing_blinding_factor(last.amount, last.asset_blinding, input_entries, other_entries)`.
   - inputs: each spent output `(value, recorded_vbf_or_0, 0)` — read via `self._get_node(name).outputs[idx].amount`,
     mirroring the sibling unshield method;
   - other outputs: the vertex's transparent outputs `(value, 0, 0)`, **the total fee** `(fee, 0, 0)`, and the
     first n‑1 shielded outputs `(value, vbf, asset_blinding)`.
   - **Fee timing subtlety:** `_add_or_augment_shielded_fee` runs *after* this method, so the shielded fee
     isn't on the vertex yet — we compute it ourselves as
     `Σ FEE_PER_{AMOUNT,FULL}_SHIELDED_OUTPUT` (1 / 2 HTR) plus any explicit `FeeHeader` already attached,
     to keep the value side balanced for `compute_balancing_blinding_factor`.
3. **Pass 2** — build each commitment + range proof (+ asset commitment + surjection proof for full‑shielded)
   using the **finalized** blindings, so the range proof is consistent with the reconciled commitment.

**Result:** the reconciliation works for **both** modes — passing each output's `asset_blinding` as the
generator‑blinding argument let `compute_balancing_blinding_factor` reconcile the full‑shielded generator
dimension too, so full‑shielded txs verify without extra work.

---

## 4. File‑by‑file walkthrough

**`hathor/dag_builder/vertex_exporter.py` (modified — the ⚠️ core patch).**
`add_shielded_outputs_header_if_needed` rewritten as the two‑pass build above. Behaviour for any
non‑shielded vertex is unchanged (early `return` when there are no shielded outputs). The docstring carries
the full rationale so the deviation is obvious to anyone reading the core file, not just this CP.

**`tps_benchmarking/benchmarks/engine/spikes/spike_cp7_shielded.py` (new).**
A throwaway, standalone de‑risk spike (no engine imports). It (A) round‑trips the native crypto
(commit→range‑proof→verify), (B) stands up a node with `ENABLE_SHIELDED_TRANSACTIONS=ENABLED` (the
`TestBuilder(settings)` + `SimulatorCpuMiningService` + `_build_vertex_verifiers` recipe from the branch's
own shielded test, combined with our harness's reactor‑init ordering), builds a tx with both shielded output
kinds, **drives every vertex through real verification**, and asserts the shielded txs are accepted and not
voided, and (C) prints the serialized‑size blow‑up. This spike is the blueprint for the CP‑8 harness change
(enable the flag in `NodeHarness`) and `workload/shielded.py`.

---

## 5. Verified

```text
# (A) native crypto round-trips; range proof is Borromean 40-bit (~3213 B), NOT the
#     stale "~675 B Bulletproof" the docstrings claim.
(A) crypto round-trip : commitment=33B range_proof=3213B verify=True

# (B) shielded txs BUILD and VERIFY end-to-end (both modes accepted, not voided)
    node: network=unittests shielded_enabled=enabled
(B) tx_full  : shielded_outputs=2 accepted=True serialized=7057B      # 2x full-shielded
(B) tx_amt   : shielded_outputs=2 accepted=True serialized=6857B      # 2x amount-shielded
SPIKE RESULT: PASS ✓  (crypto=ok, build+verify=ok)

# size profile (1 output): transparent tx 258B | amount-shielded 3546B | full-shielded 3647B
#   -> per shielded output ~3.3 KB vs ~34 B transparent (~97x); range proof 3213B dominates;
#      surjection only 67B (builder uses a trivial single-token domain).

# (C) transparent baseline STILL RUNS on the new shielded base (integration smoke)
$ python -m hathor_tps_bench run --tx-type organic --num-txs 30 -w 5
[result] accepted 30/30
  S1 142.6  S2 59.7  S3S4 1072.0  S5 919.6  S6 1158.4  TOTAL 3352.3 us
  processing throughput : 298 tx/s        # small N; double-validate intact (S3S4 ~= S6)
```

How to run them:

```bash
cd /home/lyzah/hathor-projects/p6_tps_benchmark/hathor-core
VENV=/home/lyzah/.cache/pypoetry/virtualenvs/hathor-4nrGODYv-py3.11/bin/python
# spike:
PYTHONPATH=$PWD poetry run python tps_benchmarking/benchmarks/engine/spikes/spike_cp7_shielded.py
# transparent baseline:
( cd tps_benchmarking/benchmarks/engine
  PYTHONPATH="$PWD/../../..:$PWD" $VENV -m hathor_tps_bench run --tx-type organic --num-txs 30 -w 5 )
```

---

## 6. The diff (A → B)

### 6a. Core patch — `hathor/dag_builder/vertex_exporter.py` (+92/‑33) ⚠️

```diff
@@ class VertexExporter:
     def add_shielded_outputs_header_if_needed(self, node: DAGNode, vertex: BaseTransaction) -> None:
-        """Collect outputs with [shielded] or [full-shielded] attrs into a ShieldedOutputsHeader."""
+        """Collect outputs with [shielded] or [full-shielded] attrs into a ShieldedOutputsHeader.
+
+        BALANCE RECONCILIATION (benchmark patch — see below).
+        ... [full rationale in the docstring] ...
+        """
         import os
         from hathor.crypto.shielded import (
+            compute_balancing_blinding_factor,
             create_asset_commitment, create_commitment, create_range_proof,
             create_surjection_proof, derive_asset_tag, derive_tag,
         )
         ...
-        shielded_outputs: list[ShieldedOutput] = []
+        ZERO = bytes(32)  # zero scalar (transparent entries carry blinding == 0)
 
+        # ---- PASS 1: collect one spec per shielded output + assign blindings -------------
+        specs: list[dict] = []
         for dsl_index, txout in enumerate(node.outputs):
             ... (collect amount/token/script/ephemeral keys/nonce/is_full) ...
+            specs.append({..., 'blinding': os.urandom(32),
+                          'asset_blinding': os.urandom(32) if is_full else ZERO})
+        if not specs:
+            return
+
+        # ---- reconcile the LAST output's value blinding so sum(C_in)==sum(C_out)+fee*H ----
+        input_entries = []
+        for tx_name, out_idx in node.inputs:
+            spent_output = self._get_node(tx_name).outputs[out_idx]
+            in_bf = self._shielded_blinding_factors.get((tx_name, out_idx), ZERO)
+            input_entries.append((spent_output.amount, in_bf, ZERO))
+        other_entries = [(o.value, ZERO, ZERO) for o in vertex.outputs]
+        total_fee = (explicit FeeHeader HTR entries)
+                  + Σ FEE_PER_{FULL,AMOUNT}_SHIELDED_OUTPUT over specs   # fee added later by _add_or_augment
+        if total_fee: other_entries.append((total_fee, ZERO, ZERO))
+        for s in specs[:-1]: other_entries.append((s['amount'], s['blinding'], s['asset_blinding']))
+        last = specs[-1]
+        last['blinding'] = compute_balancing_blinding_factor(
+            last['amount'], last['asset_blinding'], input_entries, other_entries)
+        # record all finalized blindings into self._shielded_blinding_factors
+
+        # ---- PASS 2: build commitments/proofs with the finalized blindings ----------------
+        shielded_outputs: list[ShieldedOutput] = []
+        for s in specs:
+            ... (build FullShieldedOutput / AmountShieldedOutput exactly as before,
+                 using s['blinding'] / s['asset_blinding']) ...
-        if not shielded_outputs:
-            return
         assert isinstance(vertex, Transaction)
         header = ShieldedOutputsHeader(tx=vertex, shielded_outputs=shielded_outputs)
         vertex.headers.append(header)
```

*(Full verbatim diff: `git diff backup/tps-benchmarking-pre-shielded..tool/tps-bench-shielded -- hathor/dag_builder/vertex_exporter.py`,
or `git show` on the eventual commit. The hunk above is elided only for the proof‑building body, which is
byte‑for‑byte the original code moved into Pass 2.)*

### 6b. New file — `spikes/spike_cp7_shielded.py`
Standalone de‑risk spike (see §4). ~150 lines; not imported by the engine.

---

## 7. Next

- **CP‑8 — shielded workload sources.** Add `workload/shielded.py`:
  `AmountShieldedTxSource` (`amount-shielded`) and `FullShieldedTxSource` (`full-shielded`, the default for a
  bare `--shielded`), subclassing `TransparentTxSource` and overriding only the per‑output DSL emit to add the
  `[shielded]`/`[full-shielded]` attribute. Teach `NodeHarness` to enable `ENABLE_SHIELDED_TRANSACTIONS`
  (+ simulator mining/verifiers) per the spike. Bar = CP‑3's: build a provably‑acceptable shielded batch with
  exact shape, all accepted under real verification.
- **CP‑9 — measure + flags + findings.** `--amount-shielded` / `--full-shielded` / `--shielded`(=full),
  single shape; run S1–S6; confirm the crypto cost lands in S3S4 **and again in S6** (the double‑validate
  amplifier); shielded‑vs‑transparent baseline numbers folded into the RFC/report.
- **Phase B (CP‑10+).** Refactor `WorkloadConfig` into a list of *segments* for mixed/superposition and
  `--mult-batches` (tx‑type changes mid‑batch, to watch TPS shift on the fly).
