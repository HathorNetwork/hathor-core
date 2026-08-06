"""The declarative P1-P12 scenario matrix — the *what*, with no node and no hathor imports.

Split out of `report_data.py` (the *how*) so it can be read by anything that needs the matrix
without paying for a hathor import or a reactor: the benchmark UI renders its scenario cards
straight from `SCENARIOS`, which is why the two can never drift out of sync.

`report_data.py` re-exports every name here, so existing imports of it keep working.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SECTIONS =("s1", "s2", "s3s4", "s5", "s6")
ALL_ON = {s: True for s in SECTIONS}
# The transparent workload every scenario uses. Moved from `1-tip-transparent` to the 3-tip mesh
# (2026-08-06): mainnet runs ~2-3 tips, and a layer of 3 leaves its transactions mutually
# independent instead of chaining each to its predecessor. Costs nothing — the s5 optimizations
# removed the O(tip-count) consensus scan. NOTE: figures collected before this change used the
# 1-tip chain and are not strictly comparable.
TRANSPARENT = "3-tip-transparent"
SHIELDED = "capless-full-shielded"          # truly confidential in+out (locked decision)
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "report-data"


def _opt_off(section: str) -> dict[str, bool]:
    """all sections ON except `section` (P10 per-section isolation)."""
    return {s: (s != section) for s in SECTIONS}


@dataclass
class Cell:
    i: int
    o: int
    label: str                              # short id used for filenames, e.g. "8i2o", "no-opt", "no-s5"
    bits: int = 64
    opt: dict[str, bool] | None = None      # None → all-ON (--opt). Sets NodeHarness(opt=...)
    workload: str | None = None             # override the scenario workload (P6/P7 "both")
    transition: str | None = None           # P11 only: "T2S" | "S2T" — a two-segment multibatch stream
    # Verification-pool overrides (None → harness default). `workers` is the single-thread vs
    # multi-core axis; see the OnceLock caveat in report_data._script_kwargs before sweeping it.
    script_mode: str | None = None          # disabled | threads | processes | rust | shadow-rust
    workers: int | None = None
    min_inputs: int | None = None


@dataclass
class Scenario:
    id: str
    title: str
    workload: str
    cells: list[Cell]
    n: int
    warmup: int
    k: int = 3
    shielded: bool = False                   # scenario default; a cell's own workload can override
    cost: int = 0                            # light→heavy ordering hint for --all
    deferred: str = ""                       # non-empty → skip in Stage 1 (needs a dedicated runner)
    note: str = ""


def _io(i: int, o: int) -> str:
    return f"{i}i{o}o"


def _scaling(workload: str, ios: list[tuple[int, int]]) -> list[Cell]:
    return [Cell(i, o, _io(i, o)) for i, o in ios]


# --------------------------------------------------------------------------------------------------
# The P1–P11 matrix (reconstructed + locked decisions applied). N / warmup are the report-scale
# values; --smoke shrinks them for plumbing checks.
# --------------------------------------------------------------------------------------------------
SCENARIOS: list[Scenario] = [
    Scenario("P1", "transparent baseline", TRANSPARENT,
             _scaling(TRANSPARENT, [(1, 2)]), n=5000, warmup=200, cost=10),
    Scenario("P2", "transparent input scaling", TRANSPARENT,
             _scaling(TRANSPARENT, [(1, 2), (2, 2), (4, 2), (8, 2)]), n=5000, warmup=200, cost=40),
    Scenario("P3", "shielded baseline", SHIELDED,
             _scaling(SHIELDED, [(1, 2)]), n=2000, warmup=200, shielded=True, cost=30),
    Scenario("P4", "shielded input scaling", SHIELDED,
             _scaling(SHIELDED, [(1, 2), (2, 2), (4, 2), (8, 2)]), n=2000, warmup=200,
             shielded=True, cost=80),
    Scenario("P5", "shielded output scaling", SHIELDED,
             _scaling(SHIELDED, [(2, 2), (2, 4), (2, 8)]), n=2000, warmup=200, shielded=True, cost=60),
    Scenario("P6", "transparent vs shielded", SHIELDED, [
        Cell(1, 2, "transparent", workload=TRANSPARENT),
        Cell(1, 2, "shielded", workload=SHIELDED),
    ], n=2000, warmup=200, shielded=True, cost=25),
    Scenario("P7", "transparent vs shielded, scaled", SHIELDED, [
        Cell(i, o, f"{tag}-{_io(i, o)}", workload=wl)
        for (tag, wl) in (("transparent", TRANSPARENT), ("shielded", SHIELDED))
        for (i, o) in [(1, 2), (4, 4), (8, 8)]
    ], n=2000, warmup=200, shielded=True, cost=90),
    Scenario("P8", "shielded surjection grid", SHIELDED,
             _scaling(SHIELDED, [(i, o) for i in (2, 4, 8) for o in (2, 4, 8)]),
             n=1000, warmup=100, shielded=True, cost=100),
    Scenario("P9", "opt vs no-opt", TRANSPARENT, [
        Cell(1, 2, "opt", opt=dict(ALL_ON)),
        Cell(1, 2, "no-opt", opt={s: False for s in SECTIONS}),
    ], n=5000, warmup=200, cost=20),
    Scenario("P10", "per-section isolation", TRANSPARENT,
             [Cell(1, 2, "full", opt=dict(ALL_ON))]
             + [Cell(1, 2, f"no-{s}", opt=_opt_off(s)) for s in SECTIONS],
             n=5000, warmup=200, cost=50),
    Scenario("P11", "transition (multi-batch)", "multibatch",
             [Cell(i, o, f"{d}-{_io(i, o)}", transition=d)
              for d in ("T2S", "S2T") for (i, o) in [(1, 2), (2, 4), (4, 8)]],
             n=1000, warmup=0, shielded=True, cost=110,
             note="two-segment stream (n each); transparent↔full-shielded, driven continuously"),
    Scenario("P12", "range-proof bit-width", SHIELDED,
             [Cell(1, 2, f"RP{b}", bits=b) for b in (32, 48, 64)],
             n=2000, warmup=200, shielded=True, cost=65,
             note="shielded 1i2o at RP = 32/48/64 bits — the proof cost/size dial"),
]
SCN_BY_ID = {s.id: s for s in SCENARIOS}
