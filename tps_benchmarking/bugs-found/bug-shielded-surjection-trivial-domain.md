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
| **Status** | Root-caused; **fix deferred** (a non-trivial surjection-domain construction). Worked around in the benchmark by restricting full-shielded to ≤1 input. |

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

## 3. Why upstream / earlier work never caught it

Every shielded path exercised so far used **exactly one input**:

- the branch's `test_shielded_dag_builder.py` builds shielded-output txs with no explicit inputs (filler adds
  one) and never drives them through verification anyway;
- our Phase-A measurements (CP-9 / CP-10) used `I=1` throughout (`num_inputs=1`), so the trivial domain always
  matched.

The first time a full-shielded tx had >1 input was the CP-11 **mixed** workload (e.g. transparent inputs +
shielded inputs in one tx), which immediately surfaced it.

## 4. Fix (deferred)

Build the surjection domain from the transaction's **actual inputs**, mirroring the verifier: one entry per
input, using each input's asset generator (transparent inputs → the unblinded token asset tag; shielded
inputs → the spent output's `asset_commitment`). This is more involved than the Pedersen-balance fix because
it must reconstruct the exact input-asset set the verifier derives. Deferred pending focused work + tests.

## 5. Workaround (benchmark)

- **AMOUNT_ONLY shielded** (`amount-shielded`, `mixed-amount`) has **no surjection proof** and works at any
  input count — use it for multi-input mixed workloads.
- **FULLY_SHIELDED** (`full-shielded`, `mixed-full`) is restricted to **≤1 total input** until the domain fix
  lands.

## 6. Suggested upstream follow-ups

1. Construct the surjection domain from the real inputs in `add_shielded_outputs_header_if_needed` (§4).
2. Add a test that builds and **verifies** a `[full-shielded]` tx with **>1 input** — the missing coverage
   that hid this (mirror the existing single-input cases at I≥2).
