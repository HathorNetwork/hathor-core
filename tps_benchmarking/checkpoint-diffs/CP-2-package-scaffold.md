# Checkpoint CP‑2 — Package scaffold

- **Snapshot A:** end of CP‑1 — only the throwaway spike exists (`spikes/spike_cp1.py`).
- **Snapshot B:** the `hathor_tps_bench` package skeleton — config, metrics model, plugin
  registries, and a working CLI — all importable and exercised, with **no** `hathor` import yet.
- **Status:** PASS ✓ (`list`, `validate`, `run` stub, and clean imports all work)
- **Files changed:** 12 new files, 523 insertions. Zero new dependencies.

---

## 1. Summary

CP‑2 lays the skeleton the rest of the engine hangs off: a typed, validated **configuration**, the
**metrics data model** that every later stage reads and writes, the two **plugin registries** that
keep the design extensible, and a small **CLI** to drive it all. It deliberately imports nothing from
`hathor`, so it can be run and tested in a fraction of a second without booting a node — the heavy
node wiring starts in CP‑3.

---

## 2. Why a scaffold checkpoint, and why these choices

**Why build the skeleton before the node.** The risky, node‑touching parts (CP‑3 harness, CP‑4
probes) are much easier to write once the *shapes* they produce and consume already exist and are
tested. If `TxRecord`, `BatchResources`, and the config are settled and validated in isolation, then
CP‑3/CP‑4 only have to fill them in — they don't also have to invent them. So this checkpoint front‑
loads all the boring‑but‑foundational decisions while they're cheap to change.

**Why it's deliberately hathor‑free.** Importing `hathor` is expensive (it pulls in Twisted, RocksDB
bindings, and — as CP‑1 showed — needs an env var and a reactor initialised *before* import). Keeping
config/metrics/registries/CLI free of that means this layer runs instantly and can be unit‑tested
without any of that ceremony. It also enforces a clean separation: configuration and data shapes have
no business knowing how a node is built.

**Why dataclasses + argparse (no pydantic/typer).** The engine lives *inside* hathor‑core's poetry
environment, which does not ship pydantic, click, or typer. Rather than add dependencies to a
blockchain node's lockfile just for a benchmark, CP‑2 uses only the standard library plus `pyyaml`
(already present). The custom `_build` loader gives us the one pydantic feature we actually need —
nested construction with friendly "unknown key" errors — in ~20 lines.

**Why registries now.** The RFC promises the engine grows along two axes: more transaction *types*
(transparent → token‑creation → nano → fee → shielded) and more *cost sources* (node‑only → wallet →
relay → confirmation). Both are realised as plugins that register themselves by name. Standing the
registries up now — even empty — means every later module plugs into a seam that already exists, and
the CLI's `list` can always report what's available.

---

## 3. File‑by‑file walkthrough

**`config.py` — the scenario, typed and validated.**
A run is described by one YAML file, and this module turns it into a tree of dataclasses
(`RootConfig` → `WorkloadConfig`, `EnvConfig`, `MeasureConfig`, `ReportingConfig`). It does two kinds
of checking, and the distinction matters. *Structural* validation happens during loading: the `_build`
helper resolves the (string) annotations to real types so it can recurse into nested dataclasses, and
it **rejects unknown keys** with a clear message — so a typo like `num_inputz` fails loudly instead of
being silently ignored. *Semantic* validation is each section's `validate()` method returning a list
of human‑readable problems (e.g. "workload.num_inputs must be >= 1"), all collected and shown at once
rather than one‑at‑a‑time. The module also defines `STAGES = ("S1","S2","S3S4","S5","S6")`, the single
source of truth for the pipeline‑stage keys used everywhere downstream.

**`metrics/model.py` — the data model the whole engine speaks.**
This is the contract between the driver (which *produces* measurements), the analysis layer (which
*reduces* them), and the reporter (which *renders* them). It encodes the RFC's three measurement views
as distinct types so they can never be confused: `StageTiming` + `TxRecord` carry the **authoritative
per‑tx, per‑stage time** (both wall and CPU nanoseconds); `BatchResources` carries the **authoritative
per‑batch** memory/I‑O/FD totals and peaks (and computes the analytical energy estimate, `CPU_s × TDP
× util`, in one place so the assumption lives with the data); and `Sample` is one point of the
**background time‑series** used for the over‑time and versus‑N charts. `RunSummary` is the flat,
reportable reduction of all that — counts, throughput, per‑stage means, latency percentiles, resource
peaks — which CP‑5 fills and the report renders. Defining these now means CP‑3/CP‑4 have concrete
targets to populate.

**`workload/registry.py` (+ `workload/__init__.py`) — the tx‑type seam.**
A tiny registry: `@register_txtype("transparent")` attaches a builder class under a name, and
`get_txtype` / `list_txtypes` look them up. No transaction types are registered yet — the transparent
DAGBuilder source arrives in CP‑3 — but the mechanism is here, so adding nano/fee/shielded later is a
new file with a decorator, never a change to the driver.

**`benchmarks/registry.py` (+ `benchmarks/__init__.py`) — the approach seam.**
The same idea for benchmark *approaches*. Each registers with a selector `name` and the results
sub‑folder it writes to (e.g. `stage-latency` → `results/stage-latency/`), captured in a small
`BenchmarkEntry`. The runner (CP‑5) will discover approaches through this registry and the CLI's
`--select` will pick a subset — so the three approaches from the RFC slot in without special‑casing.

**`cli.py` (+ `__main__.py`) — the front door.**
A stdlib‑argparse CLI with three subcommands. `list` prints the registered tx types and benchmarks
(today: none, honestly reported). `validate --config X.yaml` loads a scenario, runs both validation
passes, and either prints the fully‑resolved config as JSON (defaults filled in) or lists every
problem and exits non‑zero — invaluable for catching mistakes before a long run. `run --config X.yaml`
is a **self‑describing stub**: it validates, then prints exactly what it *would* do and notes that the
node harness/driver land in CP‑3/CP‑4 — so the command exists and is wired, it just has nothing to
execute yet. `__main__.py` makes `python -m hathor_tps_bench` work.

**`scenarios/basic.yaml` — the worked example.**
The baseline run from the RFC made concrete: 500 transparent 1‑in/2‑out transactions, `unittests`
network, RocksDB temp‑dir, trivial PoW, with a commented‑out `n_sweep` showing how the throughput‑vs‑N
sweep is requested. It doubles as living documentation of every config key.

**`README.md` — how to run it.**
The run commands (from the `engine/` directory so the package is importable) and a table mapping each
path to its purpose and the checkpoint that introduces it.

---

## 4. Verified

```text
$ python -m hathor_tps_bench list
tx types   (0): (none registered yet)
benchmarks (0): (none registered yet)

$ python -m hathor_tps_bench validate --config scenarios/basic.yaml
VALID ✓  resolved config: { ... defaults filled ... }

$ python -m hathor_tps_bench run --config scenarios/basic.yaml
[run] would run benchmarks ['stage-latency'] on 500 transparent tx (I=1, O=2).
[run] not implemented yet — node harness/driver land in CP-3/CP-4.

# invalid config (empty benchmarks, num_inputs=0, sampler_interval=0):
INVALID (3 problem(s)):
  - benchmarks: select at least one benchmark
  - workload.num_inputs must be >= 1
  - measure.sampler_interval_s must be > 0

# unknown key is rejected structurally:
  - failed to parse config: WorkloadConfig: unknown config key(s): ['bogus_key']

# import sanity: all imports OK (no circulars)
```

---

## 5. The diff (A → B)

```diff
diff --git a/README.md b/README.md
new file mode 100644
index 00000000..f1bd9974
--- /dev/null
+++ b/README.md
@@ -0,0 +1,32 @@
+# hathor_tps_bench
+
+In-process benchmark engine for Hathor full-node transaction processing.
+Design: `tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md`.
+
+## Running
+
+The package imports nothing from `hathor` for `list`/`validate` (scaffold only); the
+node harness and driver arrive in CP-3/CP-4. Run from this `engine/` directory so the
+package is importable:
+
+```bash
+cd tps_benchmarking/benchmarks/engine
+poetry run python -m hathor_tps_bench list
+poetry run python -m hathor_tps_bench validate --config scenarios/basic.yaml
+poetry run python -m hathor_tps_bench run --config scenarios/basic.yaml   # stub until CP-4/CP-5
+```
+
+## Layout (built incrementally)
+
+| Path | Purpose | Checkpoint |
+|------|---------|-----------|
+| `config.py` | scenario config (dataclasses + YAML) | CP-2 |
+| `metrics/model.py` | per-tx / per-batch record dataclasses | CP-2 |
+| `workload/registry.py` | `TxSource` registry (tx-type plugins) | CP-2 |
+| `benchmarks/registry.py` | `Benchmark` registry (approach plugins) | CP-2 |
+| `cli.py` | `list` / `validate` / `run` | CP-2 |
+| `node/` | in-process `HathorManager` harness | CP-3 |
+| `workload/transparent.py` | DAGBuilder transparent I-in/O-out source | CP-3 |
+| `probes/`, `driver/` | per-stage timing, sampler, single-thread loop | CP-4 |
+| `analysis/` | compute, plots, CSV/markdown report | CP-5 |
+| `spikes/spike_cp1.py` | CP-1 de-risk spike (throwaway) | CP-1 |
diff --git a/hathor_tps_bench/__init__.py b/hathor_tps_bench/__init__.py
new file mode 100644
index 00000000..cf826ab8
--- /dev/null
+++ b/hathor_tps_bench/__init__.py
@@ -0,0 +1,17 @@
+"""hathor_tps_bench — in-process benchmark engine for Hathor full-node tx processing.
+
+See the RFC: tps_benchmarking/planning/003-prime-rfc-fullnode-tps-benchmark.md
+
+Package layout (built incrementally across checkpoints):
+  config.py        — run configuration (dataclasses + YAML loader)        [CP-2]
+  metrics/model.py — per-tx / per-batch record dataclasses                [CP-2]
+  workload/        — TxSource registry (+ transparent DAGBuilder source)  [CP-2 reg / CP-3 impl]
+  benchmarks/      — Benchmark registry (+ stage-latency etc.)            [CP-2 reg / CP-4 impl]
+  node/            — in-process HathorManager harness                      [CP-3]
+  probes/          — per-stage timing, sampler, storage stats             [CP-4]
+  driver/          — single-thread S1..S6 loop                            [CP-4]
+  analysis/        — compute, plots, report                               [CP-5]
+  cli.py           — `python -m hathor_tps_bench` (run / list / validate) [CP-2]
+"""
+
+__version__ = "0.0.1"
diff --git a/hathor_tps_bench/__main__.py b/hathor_tps_bench/__main__.py
new file mode 100644
index 00000000..b5617781
--- /dev/null
+++ b/hathor_tps_bench/__main__.py
@@ -0,0 +1,3 @@
+from hathor_tps_bench.cli import main
+
+raise SystemExit(main())
diff --git a/hathor_tps_bench/benchmarks/__init__.py b/hathor_tps_bench/benchmarks/__init__.py
new file mode 100644
index 00000000..168e372d
--- /dev/null
+++ b/hathor_tps_bench/benchmarks/__init__.py
@@ -0,0 +1,10 @@
+"""Benchmark approaches. The `Benchmark` registry lives here; concrete benchmarks
+(stage-latency, fullnode-ingestion, single-wallet-e2e) are added in CP-4+."""
+from hathor_tps_bench.benchmarks.registry import (
+    BENCHMARK_REGISTRY,
+    get_benchmark,
+    list_benchmarks,
+    register_benchmark,
+)
+
+__all__ = ["BENCHMARK_REGISTRY", "register_benchmark", "get_benchmark", "list_benchmarks"]
diff --git a/hathor_tps_bench/benchmarks/registry.py b/hathor_tps_bench/benchmarks/registry.py
new file mode 100644
index 00000000..552a5408
--- /dev/null
+++ b/hathor_tps_bench/benchmarks/registry.py
@@ -0,0 +1,37 @@
+"""Benchmark registry. Each benchmark declares a selector `name` and the results
+sub-folder it writes to. The runner (CP-5) discovers benchmarks via this registry;
+`--select` chooses a subset."""
+from __future__ import annotations
+
+from typing import Callable, NamedTuple, TypeVar
+
+
+class BenchmarkEntry(NamedTuple):
+    cls: type
+    output_folder: str
+
+
+BENCHMARK_REGISTRY: dict[str, BenchmarkEntry] = {}
+
+T = TypeVar("T")
+
+
+def register_benchmark(name: str, output_folder: str) -> Callable[[type[T]], type[T]]:
+    def deco(cls: type[T]) -> type[T]:
+        if name in BENCHMARK_REGISTRY:
+            raise ValueError(f"benchmark {name!r} already registered")
+        cls.name = name              # type: ignore[attr-defined]
+        cls.output_folder = output_folder  # type: ignore[attr-defined]
+        BENCHMARK_REGISTRY[name] = BenchmarkEntry(cls, output_folder)
+        return cls
+    return deco
+
+
+def get_benchmark(name: str) -> BenchmarkEntry:
+    if name not in BENCHMARK_REGISTRY:
+        raise KeyError(f"unknown benchmark {name!r}; registered: {list_benchmarks()}")
+    return BENCHMARK_REGISTRY[name]
+
+
+def list_benchmarks() -> list[str]:
+    return sorted(BENCHMARK_REGISTRY)
diff --git a/hathor_tps_bench/cli.py b/hathor_tps_bench/cli.py
new file mode 100644
index 00000000..253f280e
--- /dev/null
+++ b/hathor_tps_bench/cli.py
@@ -0,0 +1,91 @@
+"""Command-line entry point: `python -m hathor_tps_bench <command>`.
+
+Commands:
+  list                       — show registered tx types and benchmarks
+  validate --config X.yaml   — load + structurally validate a scenario, print resolved config
+  run      --config X.yaml   — run the scenario (wired up in CP-4/CP-5; stub for now)
+
+Uses stdlib argparse only (no click/typer). CP-2 is intentionally hathor-free.
+"""
+from __future__ import annotations
+
+import argparse
+import json
+import sys
+
+from hathor_tps_bench import __version__
+from hathor_tps_bench.benchmarks import list_benchmarks
+from hathor_tps_bench.config import RootConfig
+from hathor_tps_bench.workload import list_txtypes
+
+
+def _cmd_list(args: argparse.Namespace) -> int:
+    txtypes = list_txtypes()
+    benches = list_benchmarks()
+    print(f"hathor_tps_bench v{__version__}")
+    print(f"\ntx types   ({len(txtypes)}): {', '.join(txtypes) or '(none registered yet)'}")
+    print(f"benchmarks ({len(benches)}): {', '.join(benches) or '(none registered yet)'}")
+    return 0
+
+
+def _load_and_validate(path: str) -> tuple[RootConfig | None, list[str]]:
+    try:
+        cfg = RootConfig.from_yaml(path)
+    except FileNotFoundError:
+        return None, [f"config file not found: {path}"]
+    except Exception as e:  # noqa: BLE001 — surface any parse/build error cleanly
+        return None, [f"failed to parse config: {e}"]
+    return cfg, cfg.validate()
+
+
+def _cmd_validate(args: argparse.Namespace) -> int:
+    cfg, errs = _load_and_validate(args.config)
+    if errs:
+        print(f"INVALID ({len(errs)} problem(s)):", file=sys.stderr)
+        for e in errs:
+            print(f"  - {e}", file=sys.stderr)
+        return 1
+    print("VALID ✓  resolved config:")
+    print(json.dumps(cfg.to_dict(), indent=2))
+    return 0
+
+
+def _cmd_run(args: argparse.Namespace) -> int:
+    cfg, errs = _load_and_validate(args.config)
+    if errs:
+        print("config invalid; run `validate` for details", file=sys.stderr)
+        return 1
+    # Execution is wired in CP-4 (driver) / CP-5 (reporting).
+    print(f"[run] scenario '{cfg.name}' is valid.")
+    print(f"[run] would run benchmarks {cfg.benchmarks} on "
+          f"{cfg.workload.num_txs} {cfg.workload.tx_type} tx "
+          f"(I={cfg.workload.num_inputs}, O={cfg.workload.num_outputs}).")
+    print("[run] not implemented yet — node harness/driver land in CP-3/CP-4.")
+    return 0
+
+
+def build_parser() -> argparse.ArgumentParser:
+    p = argparse.ArgumentParser(prog="hathor_tps_bench", description=__doc__)
+    p.add_argument("--version", action="version", version=f"hathor_tps_bench {__version__}")
+    sub = p.add_subparsers(dest="command", required=True)
+
+    sub.add_parser("list", help="show registered tx types and benchmarks").set_defaults(fn=_cmd_list)
+
+    pv = sub.add_parser("validate", help="validate a scenario YAML")
+    pv.add_argument("--config", required=True, help="path to scenario YAML")
+    pv.set_defaults(fn=_cmd_validate)
+
+    pr = sub.add_parser("run", help="run a scenario (CP-4/CP-5)")
+    pr.add_argument("--config", required=True, help="path to scenario YAML")
+    pr.add_argument("--select", nargs="*", help="override which benchmarks to run")
+    pr.set_defaults(fn=_cmd_run)
+    return p
+
+
+def main(argv: list[str] | None = None) -> int:
+    args = build_parser().parse_args(argv)
+    return args.fn(args)
+
+
+if __name__ == "__main__":
+    raise SystemExit(main())
diff --git a/hathor_tps_bench/config.py b/hathor_tps_bench/config.py
new file mode 100644
index 00000000..82a3bbfa
--- /dev/null
+++ b/hathor_tps_bench/config.py
@@ -0,0 +1,139 @@
+"""Run configuration for the benchmark engine.
+
+Plain dataclasses + a small YAML loader (no pydantic/typer dependency). A config is
+validated structurally here; it does NOT import hathor (kept light so CP-2 is
+testable without the node). Endpoints/harness wiring happens in later checkpoints.
+"""
+from __future__ import annotations
+
+import typing
+from dataclasses import asdict, dataclass, field, fields, is_dataclass
+from pathlib import Path
+from typing import Any
+
+import yaml
+
+# Canonical pipeline-stage keys (see RFC §"The pipeline and its anchor functions").
+STAGES: tuple[str, ...] = ("S1", "S2", "S3S4", "S5", "S6")
+
+
+@dataclass
+class WorkloadConfig:
+    tx_type: str = "transparent"   # registry key
+    num_txs: int = 500
+    num_inputs: int = 1            # I
+    num_outputs: int = 2           # O
+
+    def validate(self) -> list[str]:
+        errs: list[str] = []
+        if self.num_txs < 1:
+            errs.append("workload.num_txs must be >= 1")
+        if self.num_inputs < 1:
+            errs.append("workload.num_inputs must be >= 1")
+        if self.num_outputs < 1:
+            errs.append("workload.num_outputs must be >= 1")
+        return errs
+
+
+@dataclass
+class EnvConfig:
+    network: str = "unittests"        # unittests => real verifiers + cheap PoW
+    storage: str = "rocksdb_temp"     # rocksdb_temp | memory
+    seed: int = 1234
+    trivial_pow: bool = True          # set DAA TEST_ALL_WEIGHT (weights -> 1)
+
+    def validate(self) -> list[str]:
+        errs: list[str] = []
+        if self.storage not in ("rocksdb_temp", "memory"):
+            errs.append(f"env.storage must be 'rocksdb_temp' or 'memory' (got {self.storage!r})")
+        return errs
+
+
+@dataclass
+class MeasureConfig:
+    sampler_interval_s: float = 0.1   # background /proc sampler cadence
+    tdp_watts: float = 65.0           # analytical energy: CPU_s * TDP * util
+    cpu_util: float = 1.0
+    deep_tracemalloc_sample: int = 0  # 0 = off; else N txs to deep-profile
+
+    def validate(self) -> list[str]:
+        errs: list[str] = []
+        if self.sampler_interval_s <= 0:
+            errs.append("measure.sampler_interval_s must be > 0")
+        if not (0 < self.cpu_util <= 1):
+            errs.append("measure.cpu_util must be in (0, 1]")
+        return errs
+
+
+@dataclass
+class ReportingConfig:
+    formats: list[str] = field(default_factory=lambda: ["csv", "plots", "markdown"])
+
+    _ALLOWED = ("csv", "xlsx", "plots", "markdown", "html")
+
+    def validate(self) -> list[str]:
+        return [
+            f"reporting.formats has unknown entry {f!r} (allowed: {self._ALLOWED})"
+            for f in self.formats if f not in self._ALLOWED
+        ]
+
+
+@dataclass
+class RootConfig:
+    name: str = "baseline"
+    benchmarks: list[str] = field(default_factory=lambda: ["stage-latency"])
+    n_sweep: list[int] | None = None              # batch-size sweep; None = single run
+    results_root: str = "results"
+    workload: WorkloadConfig = field(default_factory=WorkloadConfig)
+    env: EnvConfig = field(default_factory=EnvConfig)
+    measure: MeasureConfig = field(default_factory=MeasureConfig)
+    reporting: ReportingConfig = field(default_factory=ReportingConfig)
+
+    # ---- loading -------------------------------------------------------------
+    @classmethod
+    def from_dict(cls, d: dict[str, Any]) -> "RootConfig":
+        return _build(cls, d or {})
+
+    @classmethod
+    def from_yaml(cls, path: str | Path) -> "RootConfig":
+        with open(path, encoding="utf-8") as fh:
+            return cls.from_dict(yaml.safe_load(fh) or {})
+
+    def to_dict(self) -> dict[str, Any]:
+        return asdict(self)
+
+    # ---- validation ----------------------------------------------------------
+    def validate(self) -> list[str]:
+        errs: list[str] = []
+        if not self.benchmarks:
+            errs.append("benchmarks: select at least one benchmark")
+        if self.n_sweep is not None and (not self.n_sweep or any(n < 1 for n in self.n_sweep)):
+            errs.append("n_sweep must be a non-empty list of positive ints (or omitted)")
+        for sub in (self.workload, self.env, self.measure, self.reporting):
+            errs.extend(sub.validate())
+        return errs
+
+
+def _build(cls: type, data: dict[str, Any]) -> Any:
+    """Recursively build a (possibly nested) dataclass from a plain dict,
+    raising a clear error on unknown keys."""
+    if not is_dataclass(cls):
+        return data
+    # Resolve string annotations (we use `from __future__ import annotations`)
+    # to real types so nested dataclasses are detected.
+    hints = typing.get_type_hints(cls)
+    known = {f.name for f in fields(cls)}
+    unknown = set(data) - known
+    if unknown:
+        raise ValueError(f"{cls.__name__}: unknown config key(s): {sorted(unknown)}")
+    kwargs: dict[str, Any] = {}
+    for name in known:
+        if name not in data:
+            continue
+        value = data[name]
+        ftype = hints.get(name)
+        if is_dataclass(ftype) and isinstance(value, dict):
+            kwargs[name] = _build(ftype, value)
+        else:
+            kwargs[name] = value
+    return cls(**kwargs)
diff --git a/hathor_tps_bench/metrics/__init__.py b/hathor_tps_bench/metrics/__init__.py
new file mode 100644
index 00000000..d8265c8f
--- /dev/null
+++ b/hathor_tps_bench/metrics/__init__.py
@@ -0,0 +1,10 @@
+"""Metrics data model + collector (collector lands in CP-4)."""
+from hathor_tps_bench.metrics.model import (
+    BatchResources,
+    RunSummary,
+    Sample,
+    StageTiming,
+    TxRecord,
+)
+
+__all__ = ["StageTiming", "TxRecord", "Sample", "BatchResources", "RunSummary"]
diff --git a/hathor_tps_bench/metrics/model.py b/hathor_tps_bench/metrics/model.py
new file mode 100644
index 00000000..dc0901ea
--- /dev/null
+++ b/hathor_tps_bench/metrics/model.py
@@ -0,0 +1,110 @@
+"""The metrics data model.
+
+Three views, matching the RFC's measurement scheme:
+  - per-tx, per-stage TIME           -> TxRecord.stages (authoritative)
+  - per-batch memory / I-O / FDs      -> BatchResources (authoritative)
+  - background time-series            -> Sample (for over-time / vs-N charts)
+RunSummary is the reduced, reportable result (filled by analysis in CP-5).
+"""
+from __future__ import annotations
+
+from dataclasses import dataclass, field
+
+from hathor_tps_bench.config import STAGES
+
+
+@dataclass
+class StageTiming:
+    """Cost of one pipeline stage for one transaction."""
+    wall_ns: int = 0   # time.perf_counter_ns delta
+    cpu_ns: int = 0    # time.process_time_ns delta
+
+
+@dataclass
+class TxRecord:
+    """Per-transaction record. `stages` maps a stage key (see config.STAGES) to its timing."""
+    index: int
+    tx_id: str
+    n_inputs: int
+    n_outputs: int
+    size_bytes: int
+    accepted: bool = False
+    error: str | None = None
+    stages: dict[str, StageTiming] = field(default_factory=dict)
+
+    def total_wall_ns(self) -> int:
+        return sum(s.wall_ns for s in self.stages.values())
+
+    def total_cpu_ns(self) -> int:
+        return sum(s.cpu_ns for s in self.stages.values())
+
+
+@dataclass
+class Sample:
+    """One background time-series sample (read from /proc)."""
+    t_rel_s: float        # seconds since batch start
+    tx_done: int          # how many txs processed by this instant
+    rss_bytes: int
+    num_fds: int
+    io_read_bytes: int    # cumulative since process start
+    io_write_bytes: int
+
+
+@dataclass
+class BatchResources:
+    """Authoritative per-batch resource figures (totals + peaks)."""
+    wall_s: float = 0.0
+    cpu_s: float = 0.0
+    io_read_bytes: int = 0      # delta across the batch
+    io_write_bytes: int = 0     # delta across the batch (after flush)
+    rss_start_bytes: int = 0
+    rss_peak_bytes: int = 0
+    rss_end_bytes: int = 0
+    fd_peak: int = 0
+    sst_bytes: int = 0          # rocksdb total_sst_files_size after flush
+
+    @property
+    def rss_growth_bytes(self) -> int:
+        return self.rss_end_bytes - self.rss_start_bytes
+
+    def energy_joules(self, tdp_watts: float, cpu_util: float) -> float:
+        """Analytical node energy estimate (RFC: CPU_s * TDP * util)."""
+        return self.cpu_s * tdp_watts * cpu_util
+
+
+@dataclass
+class RunSummary:
+    """Reduced, reportable result for one run (one batch). Latency fields in microseconds."""
+    name: str
+    benchmark: str
+    txtype: str
+    num_txs: int
+    num_inputs: int
+    num_outputs: int
+    # counts
+    submitted: int = 0
+    accepted: int = 0
+    rejected: int = 0
+    # throughput
+    processing_tps: float = 0.0          # N / sum(per-tx total wall)
+    processing_tps_inv_mean: float = 0.0  # 1 / mean(per-tx total wall)
+    # per-stage mean wall (us) — keyed by stage
+    stage_mean_us: dict[str, float] = field(default_factory=dict)
+    # overall latency percentiles (us)
+    lat_p50_us: float = 0.0
+    lat_p90_us: float = 0.0
+    lat_p99_us: float = 0.0
+    # resources
+    rss_peak_mb: float = 0.0
+    rss_growth_mb: float = 0.0
+    disk_write_mb: float = 0.0
+    disk_read_mb: float = 0.0
+    fd_peak: int = 0
+    energy_j: float = 0.0
+    # provenance
+    seed: int = 0
+    config_name: str = ""
+
+    @property
+    def stages(self) -> tuple[str, ...]:
+        return STAGES
diff --git a/hathor_tps_bench/workload/__init__.py b/hathor_tps_bench/workload/__init__.py
new file mode 100644
index 00000000..a60b3c2b
--- /dev/null
+++ b/hathor_tps_bench/workload/__init__.py
@@ -0,0 +1,10 @@
+"""Workload sources. The `TxSource` interface + registry live here; concrete
+sources (e.g. the transparent DAGBuilder source) are added in CP-3."""
+from hathor_tps_bench.workload.registry import (
+    TXTYPE_REGISTRY,
+    get_txtype,
+    list_txtypes,
+    register_txtype,
+)
+
+__all__ = ["TXTYPE_REGISTRY", "register_txtype", "get_txtype", "list_txtypes"]
diff --git a/hathor_tps_bench/workload/registry.py b/hathor_tps_bench/workload/registry.py
new file mode 100644
index 00000000..a08ad65e
--- /dev/null
+++ b/hathor_tps_bench/workload/registry.py
@@ -0,0 +1,30 @@
+"""TxSource registry — lets new transaction types (transparent now; token-creation,
+nano, fee, shielded later) be added without touching the driver. Concrete sources
+register themselves with @register_txtype("name")."""
+from __future__ import annotations
+
+from typing import Callable, TypeVar
+
+TXTYPE_REGISTRY: dict[str, type] = {}
+
+T = TypeVar("T")
+
+
+def register_txtype(name: str) -> Callable[[type[T]], type[T]]:
+    def deco(cls: type[T]) -> type[T]:
+        if name in TXTYPE_REGISTRY:
+            raise ValueError(f"tx type {name!r} already registered")
+        cls.name = name  # type: ignore[attr-defined]
+        TXTYPE_REGISTRY[name] = cls
+        return cls
+    return deco
+
+
+def get_txtype(name: str) -> type:
+    if name not in TXTYPE_REGISTRY:
+        raise KeyError(f"unknown tx type {name!r}; registered: {list_txtypes()}")
+    return TXTYPE_REGISTRY[name]
+
+
+def list_txtypes() -> list[str]:
+    return sorted(TXTYPE_REGISTRY)
diff --git a/scenarios/basic.yaml b/scenarios/basic.yaml
new file mode 100644
index 00000000..bad44d7a
--- /dev/null
+++ b/scenarios/basic.yaml
@@ -0,0 +1,34 @@
+# Baseline scenario — single batch, transparent 1-in/2-out transactions.
+# Validate with:  python -m hathor_tps_bench validate --config scenarios/basic.yaml
+name: baseline
+
+# Which benchmark approach(es) to run (registry keys). Only stage-latency exists
+# in early checkpoints; fullnode-ingestion / single-wallet-e2e come later.
+benchmarks:
+  - stage-latency
+
+# Optional batch-size sweep (throughput-vs-N). Omit for a single run.
+# n_sweep: [100, 500, 1000, 5000]
+
+results_root: results
+
+workload:
+  tx_type: transparent
+  num_txs: 500
+  num_inputs: 1      # I
+  num_outputs: 2     # O
+
+env:
+  network: unittests       # real verifiers + cheap PoW
+  storage: rocksdb_temp     # rocksdb_temp | memory
+  seed: 1234
+  trivial_pow: true         # DAA TEST_ALL_WEIGHT (weights -> 1)
+
+measure:
+  sampler_interval_s: 0.1
+  tdp_watts: 65.0           # analytical energy: CPU_s * TDP * util
+  cpu_util: 1.0
+  deep_tracemalloc_sample: 0
+
+reporting:
+  formats: [csv, plots, markdown]
```

---

## 6. Next

- **CP‑3** — the in‑process node harness (`node/`) and the transparent DAGBuilder workload
  (`workload/transparent.py`), including the **exact I/O‑control** (pinned output values) carried over
  from CP‑1 §2.5. This is the first checkpoint that imports `hathor`.
