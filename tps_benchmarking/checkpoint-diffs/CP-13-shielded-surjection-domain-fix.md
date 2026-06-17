# Checkpoint CP‑13 — Bug #3 fix: full‑shielded surjection over the real input domain

- **Snapshot A:** end of CP‑12 — full‑shielded verified only with exactly one transparent/amount‑shielded
  input (bug #3); multi‑input full‑shielded and any full‑shielded input failed surjection. Mult‑batches and
  multi‑input mixed‑full were limited to amount mode as a result.
- **Snapshot B:** full‑shielded verifies for **any input set** — multiple inputs, full‑shielded inputs, and
  mixed transparent+full‑shielded inputs all pass. The builder now constructs the surjection proof over the
  **real input domain**, mirroring the verifier.
- **Status:** PASS ✓ — validated across I=1/2/3/5, full‑shielded‑input, and mixed cases; controls
  (amount‑shielded, transparent, full‑shielded I=1) unaffected. The bug‑3 demonstration test is now a green
  regression guard.
- **Files changed:** ⚠️ core `hathor/dag_builder/vertex_exporter.py` (+24/‑4); `bugs-found/` doc + test updated.

---

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  ⚠️  EXTENDS THE CP-7/CP-11 CORE PATCH (hathor/dag_builder/vertex_exporter.py)  ⚠️      ║
║                                                                                        ║
║  add_shielded_outputs_header_if_needed now builds the surjection-proof domain from the  ║
║  REAL tx inputs (one entry per input, mirroring verify_surjection_proofs), replacing    ║
║  the hard-coded single-input "trivial" domain. Same file/method as the earlier          ║
║  reconciliation deviations — re-apply together if upstream rebases.                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 1. The fix

The verifier (`TransactionVerifier.verify_surjection_proofs`, `transaction_verifier.py:854‑889`) builds the
surjection domain with **one generator per input** (transparent / amount‑shielded → `derive_asset_tag(uid)`;
full‑shielded → the spent output's `asset_commitment`), in `tx.inputs` order. The builder previously made the
proof over a fixed **single‑entry** domain, so it only matched when the tx had exactly one *unblinded* input.

CP‑13 makes the builder mirror the verifier — once per tx, shared by all FullShieldedOutputs:

```python
surj_domain: list[tuple[bytes, bytes, bytes]] = []
if any(s['is_full'] for s in specs):
    for tx_name, out_idx in node.inputs:                      # same order as tx.inputs
        spent = self._get_node(tx_name).outputs[out_idx]
        in_uid = HATHOR_TOKEN_UID if spent.token == 'HTR' else self._get_token_id(spent.token)
        in_uid = in_uid.ljust(32, b'\x00') if len(in_uid) < 32 else in_uid
        in_raw = derive_tag(in_uid)
        if spent.attrs.get('full-shielded'):
            in_abf = self._shielded_asset_blinding_factors.get((tx_name, out_idx), ZERO)
            in_gen = create_asset_commitment(in_raw, in_abf)  # == the stored asset_commitment
        else:
            in_gen, in_abf = derive_asset_tag(in_uid), ZERO   # unblinded
        surj_domain.append((in_gen, in_raw, in_abf))
# per FullShieldedOutput:
surjection_proof = create_surjection_proof(raw_tag, asset_blinding, surj_domain)
```

Key points: the recorded **asset blinding** (CP‑11's `_shielded_asset_blinding_factors`) lets the builder
reconstruct a full‑shielded input's exact stored `asset_commitment`, so the create‑side domain generators
match the verifier's byte‑for‑byte; the iteration order matches `tx.inputs` (both derive from `node.inputs`).

## 2. Verified

```text
full-shielded I=2 / I=3 / I=5            OK   (were surjection FAIL)
mixed-full t3 s2 (transparent + full-shielded inputs)   OK   (was FAIL)
mixed-full t0 s2 (full-shielded inputs only)            OK   (was FAIL)
mixed-full t1 s1 (single full-shielded input)           OK   (was FAIL)
controls: full-shielded I=1, amount-shielded I=3, 1-tip-transparent I=3   OK
bugs-found/tests/test_bug3_surjection.py  ->  5/5 OK  (expectedFailure removed; now regression guards)
```

## 3. What this unblocks

- **Multi‑input `mixed-full`** (CP‑11) now verifies — full‑shielded mixed at any shape.
- **Full‑mode `--mult-batches`** (CP‑12) now works for multi‑input full‑shielded segments.
- The remaining gap for the requested 4‑segment scenario (transparent / amount / full‑10in / full‑1in in one
  run) is **mixed amount+full modes in a single mult‑batch** — i.e. per‑mode source pools — which is the
  next step (the surjection blocker is now gone).

## 4. The diff (A → B)

```diff
@@ add_shielded_outputs_header_if_needed (after recording blindings, before PASS 2)
+        # surjection domain (bug #3 fix): one entry per input, mirroring verify_surjection_proofs
+        surj_domain = []
+        if any(s['is_full'] for s in specs):
+            for tx_name, out_idx in node.inputs:
+                spent = self._get_node(tx_name).outputs[out_idx]
+                in_uid = ... (normalize) ; in_raw = derive_tag(in_uid)
+                if spent.attrs.get('full-shielded'):
+                    in_abf = self._shielded_asset_blinding_factors.get((tx_name, out_idx), ZERO)
+                    in_gen = create_asset_commitment(in_raw, in_abf)
+                else:
+                    in_gen, in_abf = derive_asset_tag(in_uid), ZERO
+                surj_domain.append((in_gen, in_raw, in_abf))
@@ full-shielded output build
-                # trivial single-input domain
-                input_gen = derive_asset_tag(token_uid)
-                domain = [(input_gen, raw_tag, bytes(32))]
-                surjection_proof = create_surjection_proof(raw_tag, asset_blinding, domain)
+                surjection_proof = create_surjection_proof(raw_tag, asset_blinding, surj_domain)
```

## 5. Notes / next

- Single‑token (HTR) workloads validated; multi‑token would reuse the same per‑token raw‑tags (already derived
  per input). No multi‑token workload exists in the engine yet.
- **Next:** per‑mode mult‑batches (amount + full segments in one timed run) to run the requested
  transparent → amount → full(10‑in) → full(1‑in) scenario and chart the surjection cost over time.
