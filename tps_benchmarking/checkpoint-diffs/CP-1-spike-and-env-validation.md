# Checkpoint CP‑1 — In‑process spike & environment validation  *(refreshed)*

- **Snapshot A:** project start — no engine code; hathor‑core env installed but unverified.
- **Snapshot B:** a passing in‑process spike that drives one real transaction through the node's
  real processing path under real verification, with **exact I‑in / O‑out control**.
- **Status:** PASS ✓ — `tx1 inputs/outputs : 1 / 2 (asked 1/2)`, accepted under real verification.
- **Files changed:** 1 new file — `tps_benchmarking/benchmarks/engine/spikes/spike_cp1.py` (throwaway).

> **Refresh note.** This supersedes the original CP‑1. The open item from the first version (§2.5,
> "exact O‑control deferred to the workload module") is now **resolved**: the spike achieves exact
> I‑in/O‑out, and §3 (new) documents how the DAGBuilder *filler* works and the measures we took to
> control it. That recipe is the foundation for the CP‑3 workload module.

---

## 1. Summary

A single throwaway script that de‑risks the riskiest assumptions of the whole engine before we write
any real modules: that we can boot a **real `HathorManager` in‑process** (no network), and that we can
build a valid transparent transaction with **`DAGBuilder`** — with a **chosen number of inputs and
outputs** — feed it through the node's **real** verification/consensus path, and have it **accepted**.

---

## 2. Why this approach — the reasoning

### 2.1 Why an *in‑process de‑risk harness*
The engine measures where the node spends time *inside* a transaction's processing (stages S1–S6),
which is invisible from outside. So the engine runs in the same Python process as the node and calls
its real functions directly. A spike answers the make‑or‑break questions for one throwaway file rather
than after a package is built on top of unverified assumptions.

### 2.2 Why the `unittests` network
We want the node's **real** verifiers (real signature checks, real `verify_pow`, real consensus —
that *is* what we measure), but on `mainnet` the minimum PoW weights are high (mining ~50 blocks + a tx
would cost millions of hashes) and DAA **test mode** is forbidden. The `unittests` network has low
weights and *permits* test mode, so `manager.daa_factory.TEST_MODE = TEST_ALL_WEIGHT` makes every
required weight **1** — changing only the proof‑of‑work difficulty, never which verifiers run. The
spike selects it exactly as hathor‑core's own tests do: by setting `HATHOR_CONFIG_YAML` to the
unittests YAML *before* importing `hathor.conf`.

### 2.3 Why build funding blocks (and why ~50 of them)
A transaction must spend existing value, and in a fresh DAG the only source is a block's **coinbase
reward**. So we mine blocks to create spendable outputs. The ~50 blocks are **not** about accumulating
value — a single coinbase (6400 on unittests) vastly over‑covers our needs. They exist for two
structural reasons: **reward‑lock maturity** (a coinbase can't be spent until `REWARD_SPEND_MIN_BLOCKS`
= 10 blocks sit on top of it) and **ordering anchors** (`b20 < dummy`, `b30 < fund`, `b45 < tx1`
sequence the txs past the lock; `tx1` must come after `b45`, so the chain must reach that height).

### 2.4 How the node is driven
`artifacts.propagate_with(manager, up_to_before="tx1")` feeds the funding vertices into the node via
`VertexHandler.on_new_relayed_vertex` (untimed setup); then we drive `tx1` ourselves through
`manager.on_new_tx` and confirm acceptance. This is precisely the "preload funding, then time the txs"
split the engine will use.

### 2.5 Exact I‑in / O‑out — **resolved** (was deferred)
The first CP‑1 could not pin the output count and deferred it. It is now solved: a small **`fund`
consolidation tx** turns one rigid coinbase into exactly the pinned UTXOs we want, and `tx1` spends
those and emits pinned outputs — both sides balanced, so the filler adds nothing. The result is an
exact `1 / 2`. The "how" requires understanding the filler, which is §3.

---

## 3. How the DAGBuilder *filling system* works — and how we control it

This is the heart of the refresh. The DSL only describes a **skeleton**: which vertices exist, which
output each spends (`<<<`), ordering (`<`), and any pinned output values (`out[i] = v`). Everything
left implicit — parents, input values, change, funding, block rewards — is completed by the
**filler** (`hathor/dag_builder/default_filler.py`, run from `DAGBuilder.build()` via
`self._filler.run()`). Understanding it is what let us get exact I/O.

### 3.1 The pieces

- **`run()`** — the orchestrator. It first types any unknown node as a `Transaction` and gives empty
  txs a default `out[0] = 1 HTR`; then it walks every vertex in **topological order**
  (`topological_sorting()`) and dispatches by kind:
  - **Block** — must have **0 inputs and at most 1 output**; its single coinbase output is set to the
    block reward, `daa_factory.create_v1().get_tokens_issued_per_block(1)` (= **6400** on unittests).
    Parents are filled to 3 (two tx‑parents + one block‑parent). Blocks are therefore **rigid**: you
    cannot freely size a block's output.
  - **Transaction** — `balance_node_inputs_and_outputs(node)` (below).
  - **Token / dummy** — token‑creation handling, then a final `dummy` reconciliation pass.
- **`calculate_balance(node)`** — returns, per token, `sum(outputs) − sum(inputs)`. A **positive**
  balance means the node emits more than it spends (a *shortfall* — it needs more input); a
  **negative** balance means it spends more than it emits (*leftover* — it needs change).
- **`balance_node_inputs_and_outputs(node)`** — the balancer. For each token it computes
  `diff = balance − node.balances` and:
  - if `diff < 0` (leftover) → it **appends a change output** for `abs(diff)` at the next free slot
    (`get_next_index`);
  - if `diff > 0` (shortfall) → it **adds an input** by calling `find_txin(diff, token)`.
- **`find_txin(amount, 'HTR')`** — the **auto‑funder**, and the crux of our difficulties. It grabs the
  singleton **`dummy`** node, makes the dummy spend genesis (`DAGInput('genesis_block', 0)`), and
  appends a dummy output of exactly `amount`, returning a `DAGInput('dummy', index)`. In other words,
  **any unfunded shortfall is silently covered by a hidden `dummy` tx that spends genesis** and hands
  out a UTXO of just the right size.
- **`get_next_index(outputs)`** — returns the first `None` slot or appends; decides where injected
  change/funding outputs land.
- **`fill_parents(node, target, candidates)`** — fills a vertex's parents (2 for txs, 3 for blocks)
  from genesis vertices (`genesis_1`, `genesis_2`) rather than the user's txs, so parent‑filling does
  not accidentally *confirm* (and thus distort) the transactions under test.
- **The `dummy` node** — a single auto‑created tx that acts as the filler's "bank": it spends genesis
  and accumulates one output per `find_txin` call. A final pass balances the dummy itself
  (`assert set(calculate_balance(dummy).keys()) == {'HTR'}`), adding the dummy's own change.

### 3.2 Why naïve attempts failed
Each failure mapped cleanly onto a filler rule:
- **Pin one small output, spend a coinbase** → the filler sized funding to the *pinned* side and we
  got **1 output of value 1** (`find_txin`/sizing balanced down to the pinned amount), not the 2 we
  asked for.
- **Pin both outputs, spend a coinbase** → exactly **2 outputs**, but the leftover/shortfall against
  the rigid 6400 coinbase made the filler **inject a second input via `find_txin`** → `[199, 1]`, i.e.
  2 inputs instead of 1.
- **Let `dummy` fund directly** → the auto‑`dummy` spends genesis, and if it isn't ordered past the
  reward lock, propagation fails with *"Reward still needs 10 to be unlocked."*

The throughline: **the filler will always rewrite the side you under‑specify** (adding inputs via the
dummy, or change outputs), so you can never control *both* counts by under‑specifying either side.

### 3.3 The measures we took to control it
Our recipe forces `calculate_balance(tx1) == 0`, so `balance_node_inputs_and_outputs` finds nothing to
do — no injected inputs, no change:
1. **Pin both sides of `tx1`.** Every output value is pinned, and every input is a UTXO of a known
   pinned value — so inputs and outputs sum to the same total and the balancer is a no‑op.
2. **Introduce a `fund` consolidation tx** to manufacture those pinned input UTXOs. Because a *block*
   output can't be sized, `fund` spends one mature coinbase (`b1.out[0]`, 6400) and emits exactly
   `n_inputs` pinned outputs of value `per`; the filler gives `fund` its own change for the 6398
   leftover (we never time or assert `fund`'s shape — it is pure setup). `tx1` then spends `fund`'s
   pinned outputs → exactly `n_inputs` inputs.
3. **Order the auto‑`dummy` past the reward lock** with `b20 < dummy`, so that wherever the filler
   does route a genesis‑funded `dummy`, its spend is mature and propagation does not reject it.
4. **Mine enough blocks** for maturity (`≥ REWARD_SPEND_MIN_BLOCKS` after `b1`) and for the ordering
   anchors (`b20`, `b30`, `b45`).

The net effect: `tx1` comes out as an honest transparent transaction with **exactly the requested I
inputs and O outputs**, valid under the real verifiers. This is the precise primitive — *consolidate a
coinbase into pinned UTXOs, then spend them into pinned outputs* — that the CP‑3 workload module will
generalise to build a whole batch.

---

## 4. Result

```text
network            : unittests
storage            : TransactionRocksDBStorage
verifiers          : TransactionVerifier        # REAL verification
cpu_mining_service : CpuMiningService            # REAL PoW (trivial at weight 1)
tx1 inputs/outputs : 1 / 2  (asked 1/2)          # EXACT I/O control
  output values    : [1, 1]
  input value(s)   : [2]
S1 deserialize     : round-trip OK
on_new_tx accepted : True
voided_by          : none
in storage         : True
first_block        : None   # unconfirmed mempool tip
NOTE               : tx1 produced 2 outputs (asked 2) — exact O-control via pinned values + fund consolidation
SPIKE RESULT       : PASS ✓
```

---

## 5. The diff (A → B)

```diff
diff --git a/spike_cp1.py b/spike_cp1.py
new file mode 100644
index 00000000..80ebe970
--- /dev/null
+++ b/spike_cp1.py
@@ -0,0 +1,141 @@
+"""
+CP-1 spike: de-risk the in-process drive + DAGBuilder workload for the TPS benchmark.
+
+Goal (throwaway script): build a real HathorManager in-process (RocksDB temp-dir,
+unittests network so REAL verifiers run cheaply), use DAGBuilder to build funding
+blocks + a single transparent tx with a chosen #inputs/#outputs, then feed that tx
+through the node's real processing path and confirm it is ACCEPTED under real
+verification. Also confirm S1 (deserialize from bytes) round-trips.
+
+Run:  poetry run python spike_cp1.py
+"""
+import os
+
+# Must be set BEFORE importing anything from hathor.conf — selects the unittests
+# network (low PoW weights, test-mode allowed), so real verification is cheap.
+from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
+os.environ.setdefault('HATHOR_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)
+
+# The global reactor must be initialized before importing test helpers, because
+# hathor_tests.utils builds an HDWallet at import time (which calls get_global_reactor).
+from hathor.reactor import initialize_global_reactor
+initialize_global_reactor(use_asyncio_reactor=True)
+
+import time
+
+from hathor.daa import TestMode
+from hathor.transaction import Transaction
+from hathor.util import Random
+from hathor_tests.dag_builder.builder import TestDAGBuilder
+from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock
+from hathor_tests.unittest import TestBuilder
+
+N_INPUTS = 1
+N_OUTPUTS = 2
+
+
+def build_manager():
+    # Use a false reactor clock to pass time
+    #   Does it pass time as it should? Correct pace?
+    clock = TestMemoryReactorClock()
+    clock.advance(time.time())
+    rng = Random(1234)
+
+    builder = TestBuilder()
+    builder.set_rng(rng).set_reactor(clock)
+    artifacts = builder.build()  # default storage is RocksDBStorage.create_temp()
+    manager = artifacts.manager
+
+    # trivial PoW: weights -> 1 (allowed on the unittests network)
+    manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT
+
+    manager.start()
+    clock.run()
+    clock.advance(5)
+    return manager, clock, artifacts
+
+
+def render_dsl(n_inputs: int, n_outputs: int) -> str:
+    # Fund tx1 by spending the coinbase output of n_inputs distinct blocks.
+    # `b45 < tx1` orders tx1 after the blocks so the rewards are unlocked.
+    #
+    # Exact I-in / O-out control. The block coinbase is large (6400) and the DAGBuilder
+    # filler *sizes/tops-up* any UNpinned funding to balance — so spending a raw coinbase
+    # lets the filler choose the input count. To pin BOTH sides we add a `fund` tx that
+    # consumes one mature coinbase and emits exactly n_inputs fully-pinned outputs (value
+    # `per` each). tx1 then spends those n_inputs outputs and emits n_outputs pinned
+    # outputs. Both sides are pinned and balanced (n_inputs*per == sum(outputs)), so the
+    # filler adds nothing to tx1 -> exactly n_inputs inputs and n_outputs outputs.
+    # Exact I-in / O-out: a `fund` tx eats one mature coinbase and emits n_inputs
+    # fully-pinned outputs (value `per` each); tx1 spends them (=> n_inputs inputs) and
+    # emits n_outputs pinned outputs. Both sides pinned + balanced => filler adds nothing
+    # to tx1. `b20 < dummy` orders the filler's auto-funder past the reward lock.
+    per = max(n_outputs, 1)              # each fund output / tx1 input value
+    total = n_inputs * per               # tx1 total value
+    base, rem = divmod(total, n_outputs)
+    lines = ["blockchain genesis b[1..50]", "b20 < dummy",
+             "b1.out[0] <<< fund"]                       # fund eats one block coinbase
+    for k in range(n_inputs):
+        lines.append(f"fund.out[{k}] = {per} HTR")
+    lines.append("b30 < fund")                           # fund after reward lock
+    for k in range(n_inputs):
+        lines.append(f"fund.out[{k}] <<< tx1")           # tx1 spends them => n_inputs inputs
+    for j in range(n_outputs):
+        v = base + (rem if j == n_outputs - 1 else 0)
+        lines.append(f"tx1.out[{j}] = {v} HTR")          # n_outputs pinned outputs
+    lines.append("b45 < tx1")
+    return "\n".join(lines)
+
+
+def main():
+    manager, clock, _ = build_manager()
+    settings = manager._settings
+    print(f"network            : {settings.NETWORK_NAME}")
+    print(f"storage            : {type(manager.tx_storage).__name__}")
+    print(f"verifiers          : {type(manager.verification_service.verifiers.tx).__name__}")
+    print(f"cpu_mining_service : {type(manager.cpu_mining_service).__name__}")
+
+    dag = TestDAGBuilder.from_manager(manager)
+    artifacts = dag.build_from_str(render_dsl(N_INPUTS, N_OUTPUTS))
+
+    # fund: propagate everything up to (but not including) tx1
+    artifacts.propagate_with(manager, up_to_before="tx1")  # Block stream comes from here.
+
+    tx1 = artifacts.get_typed_vertex("tx1", Transaction)
+    raw = bytes(tx1)
+    print(f"\ntx1.hash           : {tx1.hash_hex}")
+    print(f"tx1 inputs/outputs : {len(tx1.inputs)} / {len(tx1.outputs)}  (asked {N_INPUTS}/{N_OUTPUTS})")
+    print(f"  output values    : {[o.value for o in tx1.outputs]}")
+    print(f"  input value(s)   : {[manager.tx_storage.get_transaction(i.tx_id).outputs[i.index].value for i in tx1.inputs]}")
+    print(f"tx1 serialized     : {len(raw)} bytes, weight={tx1.weight}")
+
+    # S1: deserialize round-trips from bytes
+    reparsed = manager.vertex_parser.deserialize(raw)
+    assert reparsed.hash == tx1.hash, "deserialize round-trip mismatch"
+    print("S1 deserialize     : round-trip OK")
+
+    # S2..S6: drive the real processing path and time it coarsely
+    t0 = time.perf_counter()
+    accepted = manager.on_new_tx(tx1, propagate_to_peers=False, quiet=True)
+    dt_us = (time.perf_counter() - t0) * 1e6
+
+    meta = tx1.get_metadata()
+    in_storage = manager.tx_storage.transaction_exists(tx1.hash)
+    print(f"\non_new_tx accepted : {accepted}")
+    print(f"voided_by          : {meta.voided_by or 'none'}")
+    print(f"in storage         : {in_storage}")
+    print(f"first_block        : {meta.first_block}  (None => unconfirmed mempool tip)")
+    print(f"process time       : {dt_us:.1f} us (whole S2..S6, coarse)")
+
+    # Core de-risk: accepted under REAL verification, persisted, with the requested
+    # input AND output counts (exact O-control via pinned values — see render_dsl).
+    ok = (bool(accepted) and not meta.voided_by and in_storage
+          and len(tx1.inputs) == N_INPUTS and len(tx1.outputs) == N_OUTPUTS)
+    print(f"NOTE               : tx1 produced {len(tx1.outputs)} outputs (asked {N_OUTPUTS}) "
+          f"— exact O-control via pinned values + fund consolidation")
+    print(f"\nSPIKE RESULT       : {'PASS ✓' if ok else 'FAIL ✗'}")
+    return 0 if ok else 1
+
+
+if __name__ == "__main__":
+    raise SystemExit(main())
```

---

## 6. Next

- **CP‑3** — generalise §3.3's recipe into the transparent `DagBuilderTxSource`: fan one (or a few)
  coinbase(s) into the pinned UTXOs needed for a whole batch of N transactions, each with the
  configured I inputs / O outputs, sizing the block count from maturity + the fan‑out, not from N.
