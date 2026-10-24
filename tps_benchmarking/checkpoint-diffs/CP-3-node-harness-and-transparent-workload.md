# Checkpoint CP‑3 — Node harness + transparent DAGBuilder workload

- **Snapshot A:** end of CP‑2 — the package scaffold (config, metrics model, registries, CLI), hathor‑free.
- **Snapshot B:** a real in‑process node harness + a `transparent` workload source that builds a
  reproducible **batch** of N transactions with exact I‑in/O‑out, all accepted under real verification.
- **Status:** PASS ✓ — builds N = 30 → **1000** with exact I/O and fully‑disjoint inputs; reproducible.
- **Files changed:** 5 new + 2 modified (`cli.py`, `workload/__init__.py`).

---

## 1. Summary

CP‑3 turns the CP‑1 spike recipe into reusable modules and lifts it from one transaction to a whole
**batch**. A `NodeHarness` stands up the real node (RocksDB temp‑dir, real verifiers, weight‑1 PoW); a
`TransparentTxSource` builds N independent transparent txs — each with exactly the configured inputs
and outputs — preloads their funding into the node, and returns them as `PreparedTx` ready for the
timed loop. The CLI's `run` now exercises all of this on a real node. Nothing is *measured* yet — the
per‑stage probes and timed driver are CP‑4; CP‑3's job is to *produce a provably‑acceptable batch*.

---

## 2. Why — and the funding‑at‑scale discourse

The CP‑1 spike proved one tx. Scaling to N independent txs surfaces three problems, each solved by a
specific construction; this is the heart of CP‑3.

### 2.1 N independent txs need N×I disjoint UTXOs
For the batch to be processed without conflicts, **every tx must spend its own inputs** — if two txs
shared an input, one would be a double‑spend and get voided. So we mint **N×I distinct UTXOs** up
front and hand each tx its own slice of I. Generalising CP‑1's recipe: a `fund` tx eats a coinbase and
emits fully‑pinned UTXOs of value `per`; each `tx_t` spends I of them and emits O pinned outputs — both
sides balanced, so the filler adds nothing (exact I/O), and the inputs are disjoint by construction.

### 2.2 The 255‑output cap → multiple `fund` txs
A transaction's output **count is a single byte**, so a tx can hold at most **255 outputs** — minting
more fails at serialization with `struct.error: ubyte format requires 0 <= number <= 255` (confirmed
empirically: a single‑`fund` batch builds fine at N=200 but blows up at N=300). One `fund` tx can
therefore mint at most 255 UTXOs. The module **chunks** the N×I UTXOs across
`ceil(N*I / FUND_CHUNK)` fund txs (`FUND_CHUNK = 200`, headroom under the cap), each eating its own
coinbase. N=500 → 3 funds, N=1000 → 5 funds, all build cleanly.

### 2.3 Reward‑lock ordering of the auto‑`dummy`
As documented in CP‑1 §3, the filler's auto‑funder (`find_txin`) routes shortfalls through a hidden
`dummy` tx that spends **genesis**. A coinbase/genesis reward can't be spent until
`REWARD_SPEND_MIN_BLOCKS` (= 10) blocks sit on top of it, so if the dummy is anchored too early,
propagation dies with *"Reward still needs N to be unlocked."* (We hit exactly this at N=500 with the
dummy anchored at `b{n_funds+2}`.) The fix mirrors the spike: anchor it past the lock with
`b{lock} < dummy`.

### 2.4 Parents at scale, and the honest block count
The filler parents every tx to **genesis** (`fill_parents` uses genesis vertices, so building the
batch never *confirms* the txs and distorts the DAG). We verified the node accepts hundreds of txs all
parented to genesis. And — debunking the naïve "one block per tx" model — the funding **block count is
derived from maturity + ordering + the number of `fund` txs**, not from N: a handful of coinbases,
fanned out, funds an arbitrary number of transactions (`total_blocks = (n_funds + 12) + 5 + 3`, i.e.
~20 blocks even for N=1000).

### 2.5 Keeping `list`/`validate` hathor‑free
The harness imports hathor (and has import‑time side effects: it selects the unittests network and
initialises the reactor). To preserve CP‑2's fast, hathor‑free `list`/`validate`, the design uses
**lazy imports**: `cli.py` imports the harness only inside the `run` handler, and `workload/__init__.py`
imports `transparent` (which does its hathor work lazily inside `build()`), so the tx‑type
self‑registers **without** pulling in hathor. Net result: `list` still runs in ~0.5 s and shows
`transparent`.

---

## 3. File‑by‑file walkthrough

**`node/harness.py` (+ `node/__init__.py`) — the spike recipe, reusable.**
`NodeHarness` is the CP‑1 `build_manager` promoted to a class. The module top does the unavoidable
import‑time setup — point `HATHOR_CONFIG_YAML` at the unittests YAML *before* any `hathor.conf` import,
then initialise the global reactor *before* importing the test helpers — and is therefore documented as
"import lazily." `start()` builds a `TestBuilder` node on RocksDB temp‑dir storage (real verifiers),
flips the DAA to `TEST_ALL_WEIGHT` (weight‑1 PoW), and settles the virtual clock; `dag_builder()`
hands back a `TestDAGBuilder`; `stop()` closes the temp‑dir RocksDB. It is reproducible via `seed` and
supports `with NodeHarness() as h:`.

**`workload/base.py` — the contract.**
`TxSource` (ABC) defines `build(harness, num_txs, num_inputs, num_outputs) -> list[PreparedTx]`, and
`PreparedTx` carries the built tx, its serialized **bytes** (kept because S1 re‑parses them in the
driver), and the I/O counts. This module imports nothing from hathor (the tx is typed `Any`), so the
registry and `list` stay light.

**`workload/transparent.py` — the batch builder.**
`TransparentTxSource` (registered `@register_txtype("transparent")`). `render_dsl` emits the batch DSL:
the funding blocks, the `dummy` anchored past the reward lock, `ceil(N*I/200)` `fund` txs each minting a
chunk of pinned UTXOs, then per‑tx spending edges + pinned outputs (with `divmod` splitting the value so
each output is ≥1 and they sum exactly). `build` runs the DAG, then **preloads** every non‑target vertex
(blocks, dummy, funds) via `on_new_relayed_vertex` in topological order — skipping genesis/already‑present
— and returns the target txs as `PreparedTx`, *without* driving them (that's the driver's job). The
module imports no hathor at module level.

**`workload/__init__.py` (modified).** Now imports `transparent` so it self‑registers — kept hathor‑free.

**`cli.py` (modified).** `run` is no longer a stub: it lazily imports the harness + tx source, builds
the batch on a real node, and reports counts (built, exact‑I/O, distinct inputs). Added a `--num-txs`
override for smoke tests. `list`/`validate` are untouched and remain hathor‑free.

**`spikes/spike_cp3_batch.py` — the batch de‑risk mini‑spike.** A throwaway that proved §2.1–2.4
before the modules existed (and pinned down the 255 cap and the dummy ordering empirically).

---

## 4. Verified

```text
# list stays fast + hathor-free, now shows the tx type
$ python -m hathor_tps_bench list           ->  tx types (1): transparent     (~0.56 s)

# run builds a real batch and reports
$ python -m hathor_tps_bench run --config scenarios/basic.yaml --num-txs 500
[run] built 500 txs preloaded with funding
[run] exact I/O      : 500/500
[run] distinct inputs: 500 (expected 500)

scaling      : N = 30, 200, 300, 500, 1000  -> all exact I/O, all inputs disjoint
255 cap      : single-fund fails at N=300 (struct.error ubyte); chunked multi-fund builds N=1000
I/O shapes   : O>I (I=2,O=3), O<I (I=3,O=1), O=I (I=2,O=2)  -> all 40/40 exact
reproducible : same seed -> identical tx hashes (78b74385… == 78b74385…)
validate     : OK     (unchanged)
```

---

## 5. The diff (A → B)

### 5a. New files

```diff
diff --git a/hathor_tps_bench/node/__init__.py b/hathor_tps_bench/node/__init__.py
new file mode 100644
index 00000000..a993ce56
--- /dev/null
+++ b/hathor_tps_bench/node/__init__.py
@@ -0,0 +1,4 @@
+"""In-process node harness (imports hathor; not loaded by `list`/`validate`)."""
+from hathor_tps_bench.node.harness import NodeHarness
+
+__all__ = ["NodeHarness"]
diff --git a/hathor_tps_bench/node/harness.py b/hathor_tps_bench/node/harness.py
new file mode 100644
index 00000000..9bd55347
--- /dev/null
+++ b/hathor_tps_bench/node/harness.py
@@ -0,0 +1,85 @@
+"""In-process HathorManager harness — the reusable form of the CP-1 spike recipe.
+
+IMPORTANT: importing this module has side effects (it selects the unittests network
+and initialises the global reactor) and pulls in hathor + hathor_tests. Keep it out of
+the `list`/`validate` paths; import it lazily (e.g. inside the CLI `run` handler).
+"""
+from __future__ import annotations
+
+import os
+import time
+
+# Select the unittests network BEFORE importing anything from hathor.conf: low PoW
+# weights + test-mode allowed, so REAL verifiers run cheaply.
+from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
+
+os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)
+
+# The global reactor must exist before importing the test helpers (hathor_tests.utils
+# builds an HDWallet at import time, which calls get_global_reactor).
+from hathor.reactor import initialize_global_reactor
+
+initialize_global_reactor(use_asyncio_reactor=True)
+
+from hathor.daa import TestMode  # noqa: E402
+from hathor.util import Random  # noqa: E402
+from hathor_tests.dag_builder.builder import TestDAGBuilder  # noqa: E402
+from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock  # noqa: E402
+from hathor_tests.unittest import TestBuilder  # noqa: E402
+
+
+class NodeHarness:
+    """Builds a real in-process node: RocksDB temp-dir storage, REAL verifiers, and
+    trivial (weight-1) PoW. Reproducible via `seed`. See RFC §"Standing up the node"."""
+
+    def __init__(self, seed: int = 1234, trivial_pow: bool = True) -> None:
+        self.seed = seed
+        self.trivial_pow = trivial_pow
+        self.clock: TestMemoryReactorClock | None = None
+        self.manager = None
+        self._artifacts = None
+
+    def start(self) -> "NodeHarness":
+        self.clock = TestMemoryReactorClock()
+        # Anchor the virtual clock at a realistic wall time once (timestamps), then let
+        # startup settle. NOTE: measurements use time.perf_counter(), not this clock.
+        self.clock.advance(time.time())
+
+        builder = TestBuilder()
+        builder.set_rng(Random(self.seed)).set_reactor(self.clock)
+        self._artifacts = builder.build()  # default storage = RocksDBStorage.create_temp()
+        self.manager = self._artifacts.manager
+
+        if self.trivial_pow:
+            # weights -> 1 (only allowed on unittests/privatenet); verifiers stay REAL.
+            self.manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT
+
+        self.manager.start()
+        self.clock.run()
+        self.clock.advance(5)
+        return self
+
+    def dag_builder(self) -> TestDAGBuilder:
+        assert self.manager is not None, "call start() first"
+        return TestDAGBuilder.from_manager(self.manager)
+
+    @property
+    def vertex_parser(self):
+        return self.manager.vertex_parser
+
+    @property
+    def tx_storage(self):
+        return self.manager.tx_storage
+
+    def stop(self) -> None:
+        if self.manager is not None:
+            self.manager.stop()
+        rocksdb = getattr(self._artifacts, "rocksdb_storage", None)
+        if rocksdb is not None:
+            rocksdb.close()  # release the temp-dir RocksDB
+
+    def __enter__(self) -> "NodeHarness":
+        return self.start()
+
+    def __exit__(self, *exc) -> None:
+        self.stop()
diff --git a/hathor_tps_bench/workload/base.py b/hathor_tps_bench/workload/base.py
new file mode 100644
index 00000000..f54302e4
--- /dev/null
+++ b/hathor_tps_bench/workload/base.py
@@ -0,0 +1,42 @@
+"""The TxSource interface + the PreparedTx record.
+
+A TxSource builds a batch of valid transactions for the node under test: it constructs
+them, preloads any funding into the node (untimed setup), and returns the *target* txs
+as PreparedTx. It must NOT drive the targets through the processing pipeline — that is
+the driver's job (CP-4). This module imports nothing from hathor (so the registry and
+`list` stay light); concrete sources do their hathor work lazily inside build().
+"""
+from __future__ import annotations
+
+from abc import ABC, abstractmethod
+from dataclasses import dataclass
+from typing import Any
+
+
+@dataclass
+class PreparedTx:
+    """A built, signed, PoW-resolved target transaction plus its serialized bytes.
+
+    `raw` is kept alongside the object because S1 (deserialize) is timed by re-parsing
+    these bytes in the driver loop."""
+    tx: Any           # hathor Transaction (typed Any to avoid importing hathor here)
+    raw: bytes
+    n_inputs: int
+    n_outputs: int
+
+
+class TxSource(ABC):
+    name: str  # set by @register_txtype
+
+    @abstractmethod
+    def build(
+        self,
+        harness: Any,
+        num_txs: int,
+        num_inputs: int,
+        num_outputs: int,
+    ) -> list[PreparedTx]:
+        """Build `num_txs` independent txs (each with exactly num_inputs/num_outputs),
+        preload their funding into `harness.manager`, and return them as PreparedTx —
+        not yet driven through the pipeline."""
+        raise NotImplementedError
diff --git a/hathor_tps_bench/workload/transparent.py b/hathor_tps_bench/workload/transparent.py
new file mode 100644
index 00000000..aa9bd0d8
--- /dev/null
+++ b/hathor_tps_bench/workload/transparent.py
@@ -0,0 +1,97 @@
+"""Transparent I-in/O-out workload via DAGBuilder.
+
+Generalises the CP-1 fund-consolidation recipe to a whole batch (see
+checkpoint-diffs/CP-1 §3 for how the filler is controlled):
+
+  * `fund` txs consolidate coinbases into fully-pinned UTXOs of value `per`;
+  * each `tx_t` spends its own disjoint slice of `num_inputs` UTXOs and emits
+    `num_outputs` pinned outputs — both sides balanced, so the filler adds nothing,
+    giving exact I/O and no cross-tx conflicts.
+
+Because a transaction can hold at most 255 outputs (the count is a single byte), a
+single `fund` tx can mint at most that many UTXOs; for larger batches we use several
+`fund` txs, each eating its own coinbase. This module imports nothing from hathor.
+"""
+from __future__ import annotations
+
+import math
+from typing import Any
+
+from hathor_tps_bench.workload.base import PreparedTx, TxSource
+from hathor_tps_bench.workload.registry import register_txtype
+
+# UTXOs minted per `fund` tx. Kept below the 255 hard cap for headroom.
+FUND_CHUNK = 200
+
+
+@register_txtype("transparent")
+class TransparentTxSource(TxSource):
+    def render_dsl(self, num_txs: int, num_inputs: int, num_outputs: int) -> str:
+        per = max(num_outputs, 1)                  # value of each UTXO / each tx input
+        n_utxos = num_txs * num_inputs
+        n_funds = max(1, math.ceil(n_utxos / FUND_CHUNK))
+        lock = n_funds + 12                        # >= reward maturity (10) past last coinbase
+        tx_anchor = lock + 5
+        total_blocks = tx_anchor + 3
+        base, rem = divmod(num_inputs * per, num_outputs)  # output split (last absorbs remainder)
+
+        # chunk the UTXOs across the fund txs
+        sizes: list[int] = []
+        remaining = n_utxos
+        for _ in range(n_funds):
+            s = min(FUND_CHUNK, remaining)
+            sizes.append(s)
+            remaining -= s
+
+        # Order the filler's auto-`dummy` past the reward lock: it spends genesis, so an
+        # early anchor would trip "reward still needs N to be unlocked".
+        lines = [f"blockchain genesis b[1..{total_blocks}]", f"b{lock} < dummy"]
+        for f in range(n_funds):
+            lines.append(f"b{f + 1}.out[0] <<< fund{f}")          # one coinbase per fund
+        for f, size in enumerate(sizes):
+            for k in range(size):
+                lines.append(f"fund{f}.out[{k}] = {per} HTR")      # pinned UTXOs
+            lines.append(f"b{lock} < fund{f}")                     # after reward lock
+
+        utxos = [(f, k) for f, size in enumerate(sizes) for k in range(size)]
+        u = 0
+        for t in range(num_txs):
+            name = f"tx{t}"
+            for _ in range(num_inputs):
+                f, k = utxos[u]
+                u += 1
+                lines.append(f"fund{f}.out[{k}] <<< {name}")       # disjoint UTXO per input
+            for j in range(num_outputs):
+                v = base + (rem if j == num_outputs - 1 else 0)
+                lines.append(f"{name}.out[{j}] = {v} HTR")         # pinned outputs
+            lines.append(f"b{tx_anchor} < {name}")
+        return "\n".join(lines)
+
+    def build(self, harness: Any, num_txs: int, num_inputs: int, num_outputs: int) -> list[PreparedTx]:
+        dsl = self.render_dsl(num_txs, num_inputs, num_outputs)
+        artifacts = harness.dag_builder().build_from_str(dsl)
+
+        targets = {f"tx{t}" for t in range(num_txs)}
+        manager = harness.manager
+        by_name: dict[str, Any] = {}
+
+        # Preload everything that isn't a target tx (blocks, dummy, funds) in topological
+        # order — untimed setup. Skip vertices already present (e.g. genesis).
+        for node, vertex in artifacts.list:
+            if node.name in targets:
+                by_name[node.name] = vertex
+                continue
+            if manager.tx_storage.transaction_exists(vertex.hash):
+                continue
+            if not manager.vertex_handler.on_new_relayed_vertex(vertex):
+                raise RuntimeError(f"funding vertex {node.name!r} was rejected")
+
+        return [
+            PreparedTx(
+                tx=(tx := by_name[f"tx{t}"]),
+                raw=bytes(tx),
+                n_inputs=len(tx.inputs),
+                n_outputs=len(tx.outputs),
+            )
+            for t in range(num_txs)
+        ]
diff --git a/spikes/spike_cp3_batch.py b/spikes/spike_cp3_batch.py
new file mode 100644
index 00000000..27157c2e
--- /dev/null
+++ b/spikes/spike_cp3_batch.py
@@ -0,0 +1,115 @@
+"""
+CP-3 batch mini-spike: de-risk building a BATCH of N independent transparent txs.
+
+Generalises the CP-1 fund-consolidation recipe: one `fund` tx mints N*I pinned UTXOs;
+each tx_t spends its own I of them (distinct -> no conflicts) and emits O pinned
+outputs. Confirms, under REAL verifiers, that all N are accepted with exact I/O and
+disjoint inputs. De-risks: (1) the 255-output cap, (2) parents-at-scale (all parented
+to genesis), (3) input disjointness.
+
+Run:  poetry run python spikes/spike_cp3_batch.py
+"""
+import os
+
+from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH
+os.environ.setdefault('HATHOR_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)
+
+from hathor.reactor import initialize_global_reactor
+initialize_global_reactor(use_asyncio_reactor=True)
+
+import sys
+import time
+
+from hathor.daa import TestMode
+from hathor.transaction import Transaction
+from hathor.util import Random
+from hathor_tests.dag_builder.builder import TestDAGBuilder
+from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock
+from hathor_tests.unittest import TestBuilder
+
+# Optional CLI overrides:  python spike_cp3_batch.py [N_TXS [N_INPUTS [N_OUTPUTS]]]
+N_TXS = int(sys.argv[1]) if len(sys.argv) > 1 else 20
+N_INPUTS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
+N_OUTPUTS = int(sys.argv[3]) if len(sys.argv) > 3 else 2
+
+
+def build_manager():
+    clock = TestMemoryReactorClock()
+    clock.advance(time.time())
+    builder = TestBuilder()
+    builder.set_rng(Random(1234)).set_reactor(clock)
+    manager = builder.build().manager
+    manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT
+    manager.start()
+    clock.run()
+    clock.advance(5)
+    return manager, clock
+
+
+def render_batch_dsl(n_txs: int, n_inputs: int, n_outputs: int) -> str:
+    # One `fund` tx eats a coinbase and mints n_txs*n_inputs pinned UTXOs of value `per`.
+    # Each tx_t spends its own slice of `n_inputs` of them and emits `n_outputs` pinned
+    # outputs (both sides balanced -> filler adds nothing -> exact I/O per tx).
+    per = max(n_outputs, 1)                 # value of each fund UTXO / each tx input
+    n_utxos = n_txs * n_inputs
+    base, rem = divmod(n_inputs * per, n_outputs)
+
+    lines = ["blockchain genesis b[1..50]", "b20 < dummy", "b1.out[0] <<< fund"]
+    for u in range(n_utxos):
+        lines.append(f"fund.out[{u}] = {per} HTR")
+    lines.append("b30 < fund")
+
+    u = 0
+    for t in range(n_txs):
+        name = f"tx{t}"
+        for _ in range(n_inputs):
+            lines.append(f"fund.out[{u}] <<< {name}")     # disjoint UTXO per input
+            u += 1
+        for j in range(n_outputs):
+            v = base + (rem if j == n_outputs - 1 else 0)
+            lines.append(f"{name}.out[{j}] = {v} HTR")
+        lines.append(f"b45 < {name}")
+    return "\n".join(lines)
+
+
+def main():
+    manager, _ = build_manager()
+    print(f"network={manager._settings.NETWORK_NAME}  "
+          f"verifiers={type(manager.verification_service.verifiers.tx).__name__}")
+
+    dag = TestDAGBuilder.from_manager(manager)
+    artifacts = dag.build_from_str(render_batch_dsl(N_TXS, N_INPUTS, N_OUTPUTS))
+
+    # Funding (blocks + dummy + fund) is setup -> propagate up to and including `fund`.
+    artifacts.propagate_with(manager, up_to="fund")
+    fund = artifacts.get_typed_vertex("fund", Transaction)
+    print(f"fund outputs       : {len(fund.outputs)}  (<= 255 cap)")
+
+    accepted = 0
+    bad_io = 0
+    seen_inputs: set[tuple[bytes, int]] = set()
+    t0 = time.perf_counter()
+    for t in range(N_TXS):
+        tx = artifacts.get_typed_vertex(f"tx{t}", Transaction)
+        if len(tx.inputs) != N_INPUTS or len(tx.outputs) != N_OUTPUTS:
+            bad_io += 1
+        for i in tx.inputs:
+            seen_inputs.add((i.tx_id, i.index))
+        ok = manager.on_new_tx(tx, propagate_to_peers=False, quiet=True)
+        if ok and not tx.get_metadata().voided_by:
+            accepted += 1
+    dt = time.perf_counter() - t0
+
+    expected_distinct = N_TXS * N_INPUTS
+    print(f"txs accepted       : {accepted} / {N_TXS}")
+    print(f"exact I/O          : {N_TXS - bad_io} / {N_TXS} have {N_INPUTS}-in / {N_OUTPUTS}-out")
+    print(f"distinct inputs    : {len(seen_inputs)} (expected {expected_distinct})")
+    print(f"drive {N_TXS} txs   : {dt * 1e3:.1f} ms  (~{N_TXS / dt:.0f} tx/s, coarse)")
+
+    ok = accepted == N_TXS and bad_io == 0 and len(seen_inputs) == expected_distinct
+    print(f"\nMINI-SPIKE RESULT  : {'PASS ✓' if ok else 'FAIL ✗'}")
+    return 0 if ok else 1
+
+
+if __name__ == "__main__":
+    raise SystemExit(main())
```

### 5b. Modified files (CP‑3 hunks)

```diff
--- a/hathor_tps_bench/workload/__init__.py
+++ b/hathor_tps_bench/workload/__init__.py
@@
 from hathor_tps_bench.workload.registry import (
     TXTYPE_REGISTRY,
     get_txtype,
     list_txtypes,
     register_txtype,
 )
+
+# Import concrete sources so they self-register. This stays hathor-free: the modules
+# do their hathor work lazily inside build(), so `list`/`validate` remain light.
+from hathor_tps_bench.workload import transparent  # noqa: F401,E402  (registers "transparent")

 __all__ = ["TXTYPE_REGISTRY", "register_txtype", "get_txtype", "list_txtypes"]
```

```diff
--- a/hathor_tps_bench/cli.py   (run handler: stub -> real workload build)
+++ b/hathor_tps_bench/cli.py
@@ def _cmd_run(args):
-    # Execution is wired in CP-4 (driver) / CP-5 (reporting).
-    print(f"[run] scenario '{cfg.name}' is valid.")
-    print(f"[run] would run benchmarks {cfg.benchmarks} on "
-          f"{cfg.workload.num_txs} {cfg.workload.tx_type} tx "
-          f"(I={cfg.workload.num_inputs}, O={cfg.workload.num_outputs}).")
-    print("[run] not implemented yet — node harness/driver land in CP-3/CP-4.")
-    return 0
+    # CP-3: build the workload on a real in-process node and report it. Imports are
+    # lazy here so `list`/`validate` never pull in hathor.
+    from hathor_tps_bench.node import NodeHarness
+    from hathor_tps_bench.workload import get_txtype
+    w = cfg.workload
+    if args.num_txs:
+        w.num_txs = args.num_txs
+    source = get_txtype(w.tx_type)()
+    harness = NodeHarness(seed=cfg.env.seed, trivial_pow=cfg.env.trivial_pow).start()
+    try:
+        prepared = source.build(harness, w.num_txs, w.num_inputs, w.num_outputs)
+        exact = sum(1 for p in prepared
+                    if p.n_inputs == w.num_inputs and p.n_outputs == w.num_outputs)
+        distinct = {(i.tx_id, i.index) for p in prepared for i in p.tx.inputs}
+        print(f"[run] built {len(prepared)} txs preloaded with funding")
+        print(f"[run] exact I/O      : {exact}/{len(prepared)}")
+        print(f"[run] distinct inputs: {len(distinct)} (expected {w.num_txs * w.num_inputs})")
+    finally:
+        harness.stop()
+    return 0
@@ run subparser
+    pr.add_argument("--num-txs", type=int, dest="num_txs", help="override workload.num_txs")
```

---

## 6. Next

- **CP‑4** — the per‑stage probes (S1–S6 timing), the background `/proc` sampler, and the
  single‑thread driver that consumes the `PreparedTx` batch from CP‑3 and produces `TxRecord`s +
  `BatchResources`. This is where the engine starts *measuring*.
