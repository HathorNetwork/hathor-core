# Defect report — DAGBuilder builds shielded-output txs that fail the Pedersen balance check

> **Standalone bug write-up** (companion to `checkpoint-diffs/CP-7-shielded-base-and-native-crypto.md`,
> which records the same finding inline as part of our work). This document is self-contained so it can be
> shared or filed upstream on its own.

| | |
|---|---|
| **Component** | `hathor.dag_builder` (DAGBuilder / `VertexExporter`) on the shielded-outputs feature |
| **Branch** | `feat/shielded-outputs` (origin/HathorNetwork), tip `5ebfe178` |
| **Severity** | High for anyone *using* the builder to produce shielded txs — every shielded-**output** tx it builds is rejected by consensus. (Not a consensus/security hole: the verifier is correct; the *builder* is wrong.) |
| **Status** | Root-caused and fixed on our benchmark branch `tool/tps-bench-shielded` (see §5). |

---

## 1. Symptom

Build any transaction that carries a shielded output via the DSL — e.g.

```
tx1.out[0] = 50 HTR [full-shielded]
tx1.out[1] = 50 HTR [full-shielded]
```

— and drive it through the node (`on_new_relayed_vertex` / `manager.on_new_tx`). It is **rejected**:

```
hathor.exception.InvalidNewTransaction: full validation failed: shielded balance equation does not hold
```

Parsing succeeds and the **range and surjection proofs verify** — only the homomorphic balance fails. The
same is true for `[shielded]` (amount-only) outputs. The *unshield* direction (shielded inputs →
transparent outputs) is **not** affected.

## 2. The equation the verifier checks

`TransactionVerifier.verify_shielded_balance` (`hathor/verification/transaction_verifier.py:915`) checks,
for a tx with at least one shielded output:

```
sum(C_in) == sum(C_out) + fee * H
```

A shielded output's Pedersen commitment is `C = v*H + r*G` (value `v` on the asset generator `H`, blinding
`r` on the blinding generator `G`). Transparent inputs/outputs and fees are trivial commitments `v*H` with
`r = 0`. Subtracting, the equation holds **iff both** of these hold:

- **value balance:** `sum(v_in) == sum(v_out) + sum(v_shielded) + fee` — guaranteed by the DAGBuilder filler;
- **blinding balance:** `sum(r_in) == sum(r_out)` — i.e. for all-transparent inputs, `sum(r_shielded) == 0`.

## 3. Root cause

`VertexExporter.add_shielded_outputs_header_if_needed` (`hathor/dag_builder/vertex_exporter.py`, ~line 525)
assigns **every** shielded output an **independent random** value-blinding factor:

```python
blinding = os.urandom(32)        # one per output, never reconciled
...
self._shielded_blinding_factors[(node.name, dsl_index)] = blinding
```

Nothing constrains `sum(r_shielded)` to `0` (or to the input blinding sum). The `G` component therefore does
not cancel, and the balance equation cannot hold except by astronomically improbable accident. The builder
**does** reconcile the *opposite* direction correctly: `add_unshield_balance_header_if_needed` computes an
excess scalar `sum(r_in) − sum(r_out)` into an `UnshieldBalanceHeader` for shielded-in/transparent-out txs.
But the **shield direction** (transparent-in → shielded-out) and mixed txs were left unreconciled.

## 4. Why the existing tests don't catch it

No test drives a shielded-**output** tx through `verify_shielded_balance`:

- `hathor_tests/dag_builder/test_shielded_dag_builder.py` only **builds and inspects** (asserts output
  types, commitment/proof lengths) — it never calls the verifier.
- `hathor_tests/dag_builder/test_unshield_balance_dag_builder.py` asserts header **layout/serialization**;
  the two cases there that *do* invoke the verifier deliberately test **mutual-exclusion rejection** (a tx
  carrying both a shielded-outputs header and an unshield header), which short-circuits **before** the
  balance crypto runs.
- The correct residual-blinding construction exists only at the **FFI level** in
  `hathor_tests/tx/test_shielded_audit_equation.py::_shield_in_tx`, which builds commitments directly and
  never goes through a `Transaction` / the DAGBuilder.

So the gap is exactly between "the builder produces structurally-valid shielded outputs" and "a node accepts
them," and nothing exercises that path.

## 5. The fix

Reconcile the **last** shielded output's value blinding instead of randomising it. Assign random blindings to
the first n−1 shielded outputs, then set the last to the residual via the native helper
`compute_balancing_blinding_factor(last_value, last_generator_blinding, inputs, other_outputs)`, where:

- `inputs` = each spent output `(value, vbf, gbf)` — transparent inputs contribute `(value, 0, 0)`; shielded
  inputs contribute their recorded blinding;
- `other_outputs` = the vertex's transparent outputs `(value, 0, 0)`, the **total fee** `(fee, 0, 0)`, and
  the first n−1 shielded outputs `(value, vbf, gbf)`.

This makes `sum(r_out)` reconcile against `sum(r_in)` so the Pedersen balance holds. Implementation notes:

- It must be done in **two passes** — finalize all blindings first, *then* build commitments/range proofs —
  so the range proof is generated over the reconciled commitment.
- **Fee timing:** the shielded fee is attached by `_add_or_augment_shielded_fee`, which runs *after* the
  shielded-outputs header is built, so the fee isn't on the vertex yet at reconciliation time. It must be
  computed locally (`Σ FEE_PER_{AMOUNT,FULL}_SHIELDED_OUTPUT`, plus any pre-existing `FeeHeader`) to keep the
  value side balanced for `compute_balancing_blinding_factor`.
- Passing each output's **asset blinding** as the generator-blinding argument reconciles the full-shielded
  generator dimension too, so the same fix makes **both** `[shielded]` and `[full-shielded]` txs verify.

The full patch and its diff are in `checkpoint-diffs/CP-7-shielded-base-and-native-crypto.md` §6
(`hathor/dag_builder/vertex_exporter.py`).

## 6. Reproduction (copy-paste)

Two independent ways to confirm the defect. Both were run and produced the outputs shown.

### Test A — crypto-level root cause (branch-independent, no node, ~instant)

Shows the homomorphic sum fails when shielded-output blindings are independent randoms, and holds when the
last one is reconciled. Run with the native crypto built (`make build-shielded-crypto`):

```python
import os
import hathor_ct_crypto as lib
from hathor.crypto.shielded import create_commitment, verify_commitments_sum, compute_balancing_blinding_factor

gen, ZERO = lib.htr_asset_tag(), bytes(32)
c_in = create_commitment(100, ZERO, gen)             # 100-HTR "input": trivial commitment, blinding 0
r1 = os.urandom(32)

# UPSTREAM: every shielded output gets an INDEPENDENT random blinding.
r2 = os.urandom(32)
print(verify_commitments_sum([c_in], [create_commitment(50, r1, gen), create_commitment(50, r2, gen)]))
#  -> False    (the (r1+r2)*G term does not cancel, so sum(C_in) != sum(C_out))

# FIX: last blinding = residual via compute_balancing_blinding_factor.
r2 = compute_balancing_blinding_factor(50, ZERO, [(100, ZERO, ZERO)], [(50, r1, ZERO)])
print(verify_commitments_sum([c_in], [create_commitment(50, r1, gen), create_commitment(50, r2, gen)]))
#  -> True
```
Confirmed output: `False` then `True`.

### Test B — the actual DAGBuilder, end-to-end (the artifact for code owners)

Run on a **clean `feat/shielded-outputs` checkout** (i.e. without the §5 reconciliation patch). Stand up a
node with shielded enabled (the same recipe as the branch's own `test_shielded_dag_builder.py`), build a
`[shielded]`-output tx via the DSL, and drive it through verification:

```python
import os, time
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
os.environ.setdefault('HATHOR_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)
from hathor.reactor import initialize_global_reactor
initialize_global_reactor(use_asyncio_reactor=True)
from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import FeatureSetting
from hathor.daa import TestMode
from hathor.exception import InvalidNewTransaction
from hathor.simulator.patches import SimulatorCpuMiningService
from hathor.simulator.simulator import _build_vertex_verifiers
from hathor.util import Random
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock
from hathor_tests.unittest import TestBuilder

clock = TestMemoryReactorClock(); clock.advance(time.time())
s = get_global_settings().model_copy(update={'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED})
b = (TestBuilder(s).set_rng(Random(1234)).set_reactor(clock)
     .set_cpu_mining_service(SimulatorCpuMiningService())
     .set_vertex_verifiers_builder(_build_vertex_verifiers))
m = b.build().manager; m.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT
m.start(); clock.run(); clock.advance(5)

art = TestDAGBuilder.from_manager(m).build_from_str("""
    blockchain genesis b[1..50]
    b30 < dummy
    tx1.out[0] = 50 HTR [shielded]
    tx1.out[1] = 50 HTR [shielded]
""")
result = "ACCEPTED (no bug)"
for node, vertex in art.list:
    if m.tx_storage.transaction_exists(vertex.hash):
        continue
    try:
        m.vertex_handler.on_new_relayed_vertex(vertex)
    except InvalidNewTransaction as e:
        if node.name == 'tx1':
            result = f"REJECTED -> {e}"
        break
print("shielded-output tx result:", result)
```
Confirmed output on the unpatched upstream builder:
```text
shielded-output tx result: REJECTED -> full validation failed: shielded balance equation does not hold
```
(With the §5 reconciliation patch applied, the same script prints `ACCEPTED`.)

The cleanest form for the upstream test suite is to add the drive-and-assert-accepted step to
`hathor_tests/dag_builder/test_shielded_dag_builder.py` — exactly the coverage whose absence hid this.

## 7. Suggested upstream follow-ups (independent of our benchmark)

1. Add a test that builds a `[shielded]` / `[full-shielded]` output tx via the DSL and asserts it **passes**
   `verify_shielded_balance` (i.e. is accepted, not voided) — the missing coverage that hid this.
2. Apply the residual-blinding reconciliation in `add_shielded_outputs_header_if_needed` (our §5 fix).
3. Consider a builder-level assertion that `sum(r_shielded)` reconciles before emitting the header, to fail
   loudly at *build* time rather than at *verify* time.
