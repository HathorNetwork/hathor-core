# Defect report — full-shielded txs with >1 input fail (surjection proof built over a trivial single-input domain)

> Standalone bug write-up (companion to `../checkpoint-diffs/CP-11-mixed-superposition.md`). Third
> independent defect found in the shielded-outputs feature (after the Pedersen-balance and byte-deserialize
> bugs). Same pattern: the DAGBuilder produces a *structurally valid* shielded tx that **does not verify**,
> in a case upstream tests never exercise.

| | |
|---|---|
| **Component** | `hathor.dag_builder` (`VertexExporter.add_shielded_outputs_header_if_needed`) — surjection-proof construction |
| **Branch** | `feat/shielded-outputs` (origin/HathorNetwork), tip `5ebfe178` |
| **Severity** | High for FULLY_SHIELDED outputs: any tx with **more than one input** fails verification. AMOUNT_ONLY shielded outputs are unaffected (no surjection proof). |
| **Status** | **Fixed on branch (CP-13)** — the builder now constructs the surjection domain from the real inputs. Validated: full-shielded verifies at any input count and with full-shielded inputs. |

---

## 1. Symptom

A transaction with one or more `[full-shielded]` outputs and **>1 input** is rejected:

```
InvalidNewTransaction: full validation failed: shielded output 0: surjection proof verification failed
```

Measured (in-process node, shielded enabled):

```
full-shielded  I=1 O=2 : accepted ✓
full-shielded  I=2 O=2 : REJECTED (surjection)
full-shielded  I=3 O=2 : REJECTED (surjection)
amount-shielded I=3 O=2: accepted ✓     # no surjection proof -> unaffected
```

## 2. Root cause

A FullShieldedOutput carries a **surjection proof** that proves its (blinded) asset belongs to the set of
**input** asset tags. The builder (`add_shielded_outputs_header_if_needed`) constructs that proof over a
**hard-coded, single-entry "trivial" domain**:

```python
# hathor/dag_builder/vertex_exporter.py  (full-shielded branch)
input_gen = derive_asset_tag(token_uid)
domain = [(input_gen, raw_tag, bytes(32))]          # <-- exactly ONE entry, regardless of #inputs
surjection_proof = create_surjection_proof(raw_tag, asset_blinding, domain)
```

But the verifier (`TransactionVerifier.verify_surjection_proofs`) builds the domain from the transaction's
**actual inputs** — one entry per input. So:

- with **1 input**, the verifier's domain is also a single entry → it matches the trivial domain → the proof
  verifies;
- with **N>1 inputs**, the verifier's domain has N entries → the proof (made for a 1-entry domain) does not
  verify → rejection.

A second, related case (found in CP-12): even with **exactly one input**, if that input is a
**FullShieldedOutput**, the verifier's single domain entry is the spent output's *blinded* `asset_commitment`,
whereas the builder's trivial entry is the *unblinded* `derive_asset_tag(token_uid)` — they differ, so the
proof fails. So the trivial domain only matches when the tx's sole input is *unblinded* (transparent or
amount‑shielded). In short: full‑shielded verifies only with exactly one **transparent/amount‑shielded**
input; any full‑shielded input, or any second input, breaks it. The §4 fix (real per‑input domain) covers
both cases.

## 3. Why upstream / earlier work never caught it

Every shielded path exercised so far used **exactly one input**:

- the branch's `test_shielded_dag_builder.py` builds shielded-output txs with no explicit inputs (filler adds
  one) and never drives them through verification anyway;
- our Phase-A measurements (CP-9 / CP-10) used `I=1` throughout (`num_inputs=1`), so the trivial domain always
  matched.

The first time a full-shielded tx had >1 input was the CP-11 **mixed** workload (e.g. transparent inputs +
shielded inputs in one tx), which immediately surfaced it.

## 4. Fix (IMPLEMENTED in CP-13) — build the surjection domain from the real inputs

The builder must construct each surjection proof over **the same domain the verifier derives**. The verifier
(`TransactionVerifier.verify_surjection_proofs`, `transaction_verifier.py:854-889`) builds `domain_generators`
with **one entry per non-authority input**, in `tx.inputs` order:

| input kind | domain generator the verifier uses |
|---|---|
| transparent | `derive_asset_tag(token_uid)` (unblinded asset tag) |
| shielded `FullShieldedOutput` | the spent output's `asset_commitment` (blinded) |
| shielded `AmountShieldedOutput` | `derive_asset_tag(token_uid)` (unblinded) |
| (+ each `MintHeader` entry) | `derive_asset_tag(entry token_uid)` |

`create_surjection_proof(raw_tag, asset_blinding, domain)` needs, per domain entry, the triple
`(generator, raw_tag, asset_blinding_of_that_generator)`. So the builder's
`add_shielded_outputs_header_if_needed` should, **for each `node.input` in order**, emit:

- transparent input → `(derive_asset_tag(uid), raw_tag(uid), ZERO)`;
- shielded input → `(asset_commitment, raw_tag(uid), recorded_asset_blinding)` for full-shielded
  (the asset blinding is now available — CP-11 records it in `_shielded_asset_blinding_factors`), or
  `(derive_asset_tag(uid), raw_tag(uid), ZERO)` for amount-shielded;
- plus one entry per MintHeader entry.

Then call `create_surjection_proof(raw_tag_of_output, output_asset_blinding, that_domain)` for each
FullShieldedOutput. Two requirements: the **order must match** `tx.inputs` (the verifier iterates in order),
and the output's own asset must be present in the domain (it is, since the output spends one of those assets).

**Implemented (CP-13):** `add_shielded_outputs_header_if_needed` now builds `surj_domain` once per tx by
iterating `node.inputs` in order — transparent/amount-shielded inputs → `(derive_asset_tag(uid),
derive_tag(uid), ZERO)`, full-shielded inputs → `(create_asset_commitment(derive_tag(uid), recorded_abf),
derive_tag(uid), recorded_abf)` (the recorded asset blinding reconstructs the exact stored
`asset_commitment`) — and passes it to `create_surjection_proof` for every FullShieldedOutput. Validated:
full-shielded at I=1/2/3/5, full-shielded spending full-shielded inputs, and mixed transparent+full-shielded
inputs all verify; amount-shielded and transparent unaffected (`tests/test_bug3_surjection.py`, all green).
Single-token (HTR) only for now; multi-token mixes would need the same per-token raw-tags (already derived
from each input's token).

## 5. Workaround (obsolete after the CP-13 fix)

Before the fix, multi-input shielded workloads had to use **AMOUNT_ONLY** (`amount-shielded` / `mixed-amount`,
no surjection proof), and **FULLY_SHIELDED** was restricted to ≤1 transparent input. With the §4 fix this is
no longer needed: full-shielded verifies at any input count and with full-shielded inputs.

## 6. Suggested upstream follow-ups

1. Construct the surjection domain from the real inputs in `add_shielded_outputs_header_if_needed` (§4).
2. Add a test that builds and **verifies** a `[full-shielded]` tx with **>1 input** — the missing coverage
   that hid this (mirror the existing single-input cases at I≥2).

## 7. Reproduction test

`tests/test_bug3_surjection.py` (runnable; `unittest.TestCase`). It drives full batches through real
verification and asserts:

- `test_amount_shielded_multi_input_ok` — AMOUNT_ONLY at I=3 is **accepted** (control; no surjection proof).
- `test_full_shielded_single_input_ok` — FULLY_SHIELDED at I=1 is **accepted** (control; trivial domain matches).
- `test_full_shielded_multi_input` — FULLY_SHIELDED at I=3 verifies (was the bug; now a regression guard).
- `test_full_shielded_with_full_shielded_inputs` — a full-shielded tx spending full-shielded inputs verifies.
- `test_mixed_full_transparent_and_shielded_inputs` — transparent + full-shielded inputs with full-shielded
  outputs verifies.

After the CP-13 fix all five pass (`OK`); on the unpatched builder the three multi-input / full-shielded-input
cases fail with "surjection proof verification failed". (Before the fix, `test_full_shielded_multi_input` was
`@unittest.expectedFailure` to document the live bug; the decorator was removed once the fix landed.)

Upstream form: the same assertions translate directly to a `hathor_tests`‑style `TestCase` using the
shielded DAGBuilder recipe (e.g. `src_a/src_b.out[0] = V HTR; src_a.out[0] <<< tx; src_b.out[0] <<< tx;
tx.out[0..1] = … [full-shielded]`) driven through `verify_surjection_proofs` / `on_new_tx`.
