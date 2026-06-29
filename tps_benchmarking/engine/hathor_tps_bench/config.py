"""Run configuration for the benchmark engine.

Plain dataclasses + a small YAML loader (no pydantic/typer dependency). A config is
validated structurally here; it does NOT import hathor (kept light so CP-2 is
testable without the node). Endpoints/harness wiring happens in later checkpoints.
"""
from __future__ import annotations

import typing
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

# Canonical pipeline-stage keys (see RFC §"The pipeline and its anchor functions").
STAGES: tuple[str, ...] = ("S1", "S2", "S3S4", "S5", "S6")

# Default results location, anchored to the engine package (parents[1] == the engine dir),
# NOT the current working directory. Runs therefore always land in the same place no matter
# where the CLI is launched from — this is what prevents stray nested results/ trees when a
# command is run from the wrong cwd. Override per-run with --results-root or the config key.
DEFAULT_RESULTS_ROOT: str = str(Path(__file__).resolve().parents[1] / "results")

# ---- optimization gating (Phase-3 merge of PR #1729) --------------------------------------
# The optimized code paths are the DEFAULT (ON). Two mutually-exclusive master flags select
# per-section: --opt (opt-IN) and --no-opt (opt-OUT). Section keys mirror the measured
# pipeline stages S1..S6.
OPT_SECTIONS: tuple[str, ...] = ("s1", "s2", "s3s4", "s5", "s6")


def resolve_opt(opt: list[str] | None, no_opt: list[str] | None) -> dict[str, bool]:
    """Resolve the --opt / --no-opt selectors into a per-section ON/OFF map.

    Semantics (LOCKED 2026-06-26):
      - neither flag            -> all sections optimized (default)
      - --opt    (no sections)  -> all optimized
      - --no-opt (no sections)  -> all baseline
      - --opt    S [S...]       -> ONLY S optimized, the rest baseline   (opt-in)
      - --no-opt S [S...]       -> ONLY S baseline, the rest optimized   (opt-out)

    `opt`/`no_opt` are None when the flag is absent, else a (possibly empty) list of section
    keys. Section names are arguments OF a master flag, so a section can never be passed
    standalone (argparse enforces this). Raises ValueError if both masters are given (argparse
    already guards this via a mutually-exclusive group; the check is belt-and-suspenders).

    FUTURE (TODO): these section flags are COARSE — one boolean per section. Per-optimization
    sub-flags are planned (e.g. --mem-tips / --save-dedup / --write-batch / --binary-metadata /
    --rust-storage / --reorg-gate for S5; --rust-scripts vs --parallel-scripts for S3S4). Until
    then a section flag toggles ALL optimizations in that section together. See the
    tps_benchmarking optimizations-workstream notes and the TODO markers at each gating site.
    """
    if opt is not None and no_opt is not None:
        raise ValueError("--opt and --no-opt are mutually exclusive")
    if opt is None and no_opt is None:
        return {s: True for s in OPT_SECTIONS}
    if opt is not None:
        given = set(opt)
        return {s: (s in given) if given else True for s in OPT_SECTIONS}
    given = set(no_opt)
    return {s: (s not in given) if given else False for s in OPT_SECTIONS}


@dataclass
class WorkloadConfig:
    tx_type: str = "1-tip-transparent"  # registry key; the realistic tip-confirming baseline
    num_txs: int = 500             # K — the MEASURED txs
    num_inputs: int = 1            # I — TRANSPARENT inputs per tx
    num_outputs: int = 2           # O — TRANSPARENT outputs per tx
    # Shielded slice (only meaningful for the mixed-* tx types; the transparent slice above
    # may then be 0). For pure transparent/shielded tx types these stay 0.
    shielded_inputs: int = 0       # shielded inputs per tx (mixed-*)
    shielded_outputs: int = 0      # shielded outputs per tx (mixed-*); must be 0 or >= 2
    warmup_txs: int = 100          # W — driven but DISCARDED, to burn in caches/JIT
                                   # (steady-state; NO block — that would re-cool the cache)

    def validate(self) -> list[str]:
        errs: list[str] = []
        if self.num_txs < 1:
            errs.append("workload.num_txs must be >= 1")
        if self.num_inputs < 0 or self.shielded_inputs < 0:
            errs.append("workload.num_inputs / shielded_inputs must be >= 0")
        if self.num_outputs < 0 or self.shielded_outputs < 0:
            errs.append("workload.num_outputs / shielded_outputs must be >= 0")
        if self.num_inputs + self.shielded_inputs < 1:
            errs.append("workload: total inputs (num_inputs + shielded_inputs) must be >= 1")
        if self.num_outputs + self.shielded_outputs < 1:
            errs.append("workload: total outputs (num_outputs + shielded_outputs) must be >= 1")
        if self.shielded_outputs == 1:
            errs.append("workload.shielded_outputs must be 0 or >= 2 (verify_trivial_commitment_protection)")
        if self.warmup_txs < 0:
            errs.append("workload.warmup_txs must be >= 0")
        return errs


@dataclass
class EnvConfig:
    network: str = "unittests"        # unittests => real verifiers + cheap PoW
    storage: str = "rocksdb_temp"     # rocksdb_temp | memory
    seed: int = 1234
    trivial_pow: bool = True          # set DAA TEST_ALL_WEIGHT (weights -> 1)

    def validate(self) -> list[str]:
        errs: list[str] = []
        if self.storage not in ("rocksdb_temp", "memory"):
            errs.append(f"env.storage must be 'rocksdb_temp' or 'memory' (got {self.storage!r})")
        return errs


@dataclass
class MeasureConfig:
    sampler_interval_s: float = 0.1   # background /proc sampler cadence
    tdp_watts: float = 65.0           # analytical energy: CPU_s * TDP * util
    cpu_util: float = 1.0
    deep_tracemalloc_sample: int = 0  # 0 = off; else N txs to deep-profile

    def validate(self) -> list[str]:
        errs: list[str] = []
        if self.sampler_interval_s <= 0:
            errs.append("measure.sampler_interval_s must be > 0")
        if not (0 < self.cpu_util <= 1):
            errs.append("measure.cpu_util must be in (0, 1]")
        return errs


@dataclass
class ReportingConfig:
    formats: list[str] = field(default_factory=lambda: ["csv", "plots", "markdown"])
    window: int | None = None   # rolling-curve window; None = adaptive min(50,max(5,10%N))

    _ALLOWED = ("csv", "xlsx", "plots", "markdown", "html")

    def validate(self) -> list[str]:
        errs = [
            f"reporting.formats has unknown entry {f!r} (allowed: {self._ALLOWED})"
            for f in self.formats if f not in self._ALLOWED
        ]
        if self.window is not None and self.window < 1:
            errs.append("reporting.window must be >= 1 (or omitted for adaptive)")
        return errs


@dataclass
class RootConfig:
    name: str = "baseline"
    benchmarks: list[str] = field(default_factory=lambda: ["stage-latency"])
    n_sweep: list[int] | None = None              # batch-size sweep; None = single run
    results_root: str = DEFAULT_RESULTS_ROOT  # absolute, anchored to the engine dir; gitignored
    # Per-section optimization gating (default: all ON). Set from --opt/--no-opt via the CLI;
    # threaded into the harness/builder to select optimized-vs-baseline code paths per section.
    opt: dict[str, bool] = field(default_factory=lambda: {s: True for s in OPT_SECTIONS})
    workload: WorkloadConfig = field(default_factory=WorkloadConfig)
    env: EnvConfig = field(default_factory=EnvConfig)
    measure: MeasureConfig = field(default_factory=MeasureConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)

    # ---- loading -------------------------------------------------------------
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RootConfig":
        return _build(cls, d or {})

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RootConfig":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    # ---- validation ----------------------------------------------------------
    def validate(self) -> list[str]:
        errs: list[str] = []
        if not self.benchmarks:
            errs.append("benchmarks: select at least one benchmark")
        if self.n_sweep is not None and (not self.n_sweep or any(n < 1 for n in self.n_sweep)):
            errs.append("n_sweep must be a non-empty list of positive ints (or omitted)")
        for sub in (self.workload, self.env, self.measure, self.reporting):
            errs.extend(sub.validate())
        return errs


def _build(cls: type, data: dict[str, Any]) -> Any:
    """Recursively build a (possibly nested) dataclass from a plain dict,
    raising a clear error on unknown keys."""
    if not is_dataclass(cls):
        return data
    # Resolve string annotations (we use `from __future__ import annotations`)
    # to real types so nested dataclasses are detected.
    hints = typing.get_type_hints(cls)
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"{cls.__name__}: unknown config key(s): {sorted(unknown)}")
    kwargs: dict[str, Any] = {}
    for name in known:
        if name not in data:    # Why would it not be if unknown is empty?
            continue
        value = data[name]
        ftype = hints.get(name)
        if is_dataclass(ftype) and isinstance(value, dict):
            kwargs[name] = _build(ftype, value)
        else:
            kwargs[name] = value
    return cls(**kwargs)
