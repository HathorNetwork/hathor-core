"""Declarative registry of runnable simulations — the single source of truth for the UI form.

The front end renders controls straight from this structure (no hand-written HTML per flag), and
`run_sim.py` reads the same keys back.

Two families:

* **Custom run** — free-form exploration: any workload, any I/O, any optimization map. One cell,
  one rep. This is the card that does NOT correspond to a report scenario.
* **P1–P12** — the canonical report scenarios, GENERATED from `report_data.SCENARIOS` rather than
  restated here, so the UI can never drift from the matrix the report was built on. Each exposes
  the three knobs `report_data` itself supports as overrides (N / warm-up / k) plus range-proof
  bits and the optimization map where those are not the experiment's own variable.

Control kinds:
  number  — numeric input, plus a slider when `slider` is true
  bool    — a toggle; renders as a checkbox chip
  choice  — a small set of fixed values; renders as a segmented control
"""
from __future__ import annotations

import sys
from pathlib import Path

# report_data lives in the engine's scripts/ dir, which is not a package.
ENGINE_SCRIPTS = Path(__file__).resolve().parents[1] / "engine" / "scripts"
if str(ENGINE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(ENGINE_SCRIPTS))

WORKLOAD_LABEL = {
    "1-tip-transparent": "transparent",
    "capless-full-shielded": "shielded (capless, in+out)",
    "multibatch": "transparent ↔ shielded stream",
}

# Scenarios whose cells already vary the optimization map — exposing opt toggles there would let
# the user contradict the experiment, so those cards omit them.
OPT_IS_THE_EXPERIMENT = {"P9", "P10"}
# P12 sweeps range-proof width itself, so it must not also offer a fixed width.
BITS_IS_THE_EXPERIMENT = {"P12"}

# Report N is 1000-5000 with k=3, which is tens of minutes to hours per scenario. The UI defaults
# to something a person will actually sit through and says so; the report values stay reachable.
UI_DEFAULT_N = 300
UI_DEFAULT_WARMUP = 50
UI_DEFAULT_K = 1


def _num(key, label, lo, hi, step, default, help_, slider=True):
    return {"kind": "number", "key": key, "label": label, "min": lo, "max": hi,
            "step": step, "default": default, "help": help_, "slider": slider}


def _bool(key, label, default, help_):
    return {"kind": "bool", "key": key, "label": label, "default": default, "help": help_}


def _choice(key, label, values, default, help_, wide=False):
    """`wide` makes the control span the whole control grid — needed when the options are long
    enough that the segmented bar would otherwise overflow its track."""
    return {"kind": "choice", "key": key, "label": label, "values": values,
            "default": default, "help": help_, "wide": wide}


OPT_CONTROLS = [
    _bool("opt_s1", "S1 · ser/de", True, "Rust vertex parser"),
    _bool("opt_s2", "S2 · gate", True, "get_transaction read fast-paths"),
    _bool("opt_s3s4", "S3S4 · verify", True, "Rust script-verification pool"),
    _bool("opt_s5", "S5 · cons.", True, "Rust RocksDB, binary metadata, incremental mempool-tips"),
    _bool("opt_s6", "S6 · post-cons.", True, "Drops the redundant 2nd validate_full"),
]

ENV_CONTROLS = [
    _bool("trivial_pow", "Trivial PoW (weight = 1)", True,
          "Speeds batch setup only — verification cost is weight-independent."),
    _bool("quiet_logs", "Suppress node debug logging", True,
          "Engine default. Turn OFF to reproduce the published report figures, which were "
          "collected with the per-tx debug render inside timed S6 (~110 µs/tx)."),
]

CUSTOM = {
    "id": "custom",
    "kind": "custom",
    "title": "Custom run",
    "tag": "FREE",
    "subtitle": "Any workload, any shape — one cell, one repetition",
    "workload": "1-tip-transparent",
    "description": (
        "Free-form exploration outside the report matrix: pick a workload and transaction shape and "
        "drive it through S1–S6. Use the P-cards below to reproduce a report scenario exactly."
    ),
    "cells": 1,
    "groups": [
        {
            "label": "Workload",
            "controls": [
                _choice("workload", "Workload",
                        ["1-tip-transparent", "capless-full-shielded", "amount-shielded",
                         "full-shielded", "defunct"],
                        "1-tip-transparent",
                        "capless-full-shielded is shielded in AND out (-i/-o mean shielded counts). "
                        "defunct is the O(N²) genesis-parented pathology, kept for demonstration.",
                        wide=True),
                _num("num_txs", "Measured transactions (N)", 20, 5000, 10, UI_DEFAULT_N,
                     "Transactions actually timed. Build time grows with N."),
                _num("num_inputs", "Inputs per tx (I)", 1, 8, 1, 1,
                     "Transparent: one ECDSA signature each. Shielded: grows the surjection domain."),
                _num("num_outputs", "Outputs per tx (O)", 1, 16, 1, 2,
                     "Transparent outputs are near-free; each SHIELDED output is a range proof."),
                _num("warmup_txs", "Warm-up transactions (W)", 0, 500, 10, UI_DEFAULT_WARMUP,
                     "Driven then discarded, so the measured window is steady state."),
                _num("seed", "RNG seed", 1, 999999, 1, 1234,
                     "Same seed rebuilds the same batch.", slider=False),
                _choice("bits", "Range-proof bits", [32, 48, 64], 64,
                        "Shielded only. Narrower proofs verify and serialize proportionally cheaper."),
            ],
        },
        {"label": "Optimizations (PR #1729)",
         "note": "All on = --opt. Turn one off to isolate that section's contribution.",
         "controls": OPT_CONTROLS},
        {"label": "Environment", "controls": ENV_CONTROLS},
    ],
}


def _scenario_card(scn) -> dict:
    """Build one P-card from a report_data Scenario."""
    shielded = scn.shielded or scn.workload == "multibatch"
    cells = [c.label for c in scn.cells]
    is_multibatch = any(c.transition for c in scn.cells)

    knobs = [
        _num("num_txs", "Measured transactions per cell (N)", 20, 5000, 10,
             min(scn.n, UI_DEFAULT_N),
             f"The report used N={scn.n}. Lower is faster; the shape of the result holds."),
        _num("k", "Repetitions (k)", 1, 5, 1, UI_DEFAULT_K,
             f"The report used k={scn.k} and reports the median. Every cell is rerun k times."),
    ]
    if not is_multibatch:                       # P11 drives the transition with no warm-up
        knobs.insert(1, _num("warmup_txs", "Warm-up per cell (W)", 0, 500, 10,
                             min(scn.warmup, UI_DEFAULT_WARMUP),
                             f"The report used W={scn.warmup}; driven then discarded."))
    if shielded and scn.id not in BITS_IS_THE_EXPERIMENT:
        knobs.append(_choice("bits", "Range-proof bits", [32, 48, 64], 64,
                             "64 is the report default. Narrower proofs verify much faster, so "
                             "change it only when comparing widths."))

    groups = [{"label": "Scale",
               "note": f"{len(cells)} cell{'s' if len(cells) != 1 else ''}: {', '.join(cells)}"
                       f"  ·  total runs = cells × k",
               "controls": knobs}]
    if scn.id not in OPT_IS_THE_EXPERIMENT:
        groups.append({"label": "Optimizations (PR #1729)",
                       "note": "Applied to every cell in this scenario.",
                       "controls": OPT_CONTROLS})
    else:
        groups.append({"label": "Optimizations (PR #1729)",
                       "note": "Fixed by this experiment — the cells ARE the optimization "
                               "configurations, so there is nothing to choose here.",
                       "controls": []})
    groups.append({"label": "Environment", "controls": ENV_CONTROLS})

    note = f" {scn.note}" if scn.note else ""
    return {
        "id": scn.id,
        "kind": "scenario",
        "tag": scn.id,
        "title": scn.title[0].upper() + scn.title[1:],
        "subtitle": f"{WORKLOAD_LABEL.get(scn.workload, scn.workload)} · {len(cells)} cells",
        "workload": scn.workload,
        "cells": len(cells),
        "cost": scn.cost,
        "description": (
            f"Report scenario {scn.id}. Runs {len(cells)} cell(s) — {', '.join(cells)} — each on a "
            f"fresh funded node, then renders the same figures the report uses.{note}"
        ),
        "groups": groups,
    }


def _load_scenarios() -> list[dict]:
    # report_scenarios, NOT report_data: the former is the declarative matrix and imports nothing
    # from hathor, so the web server never pays for a node import or a reactor.
    import report_scenarios
    return [_scenario_card(s) for s in sorted(report_scenarios.SCENARIOS, key=lambda s: int(s.id[1:]))]


SIMULATIONS: list[dict] = [CUSTOM] + _load_scenarios()
BY_ID = {s["id"]: s for s in SIMULATIONS}


def defaults(sim_id: str) -> dict:
    """Every control's default, flattened — the shape `run_sim.py` expects."""
    sim = BY_ID[sim_id]
    return {c["key"]: c["default"] for g in sim["groups"] for c in g["controls"]}
