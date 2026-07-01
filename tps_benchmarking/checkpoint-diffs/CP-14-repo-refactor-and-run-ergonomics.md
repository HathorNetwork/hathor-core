# Checkpoint CP‑14 — repo refactor: run from root, env de‑friction, timestamped results

- **Snapshot A:** end of CP‑13 (review fixes committed). The engine lived at
  `tps_benchmarking/benchmarks/engine/` (a redundant double nesting — `benchmarks/` held only
  `engine/`). Running it required `cd`‑ing deep and/or `PYTHONPATH=<root>` gymnastics because
  `hathor`'s editable install was broken (no `.pth`), so `import hathor` only worked when the cwd
  *was* the repo root. Run‑output dirs had no timestamp (`baseline_..._N6_I1_O2`) and `results_root`
  was a **cwd‑relative** string, which silently produced stray nested `…/engine/tps_benchmarking/
  benchmarks/engine/results/…` trees when a command ran from the wrong directory.
- **Snapshot B:** the engine lives at `tps_benchmarking/engine/`. It runs from the `hathor-core/`
  **repo root** with no `cd` and no `PYTHONPATH` — `make tps ARGS="…"` or `poetry run hathor-tps-bench
  …` (or `python -m hathor_tps_bench …`). Imports resolve from **any** cwd. Every run/sweep/multibatch
  writes to an **absolute, engine‑anchored** results dir with a **`_YYYYMMDD-HHMMSS`** suffix, so runs
  never overwrite and always land in the same place.
- **Status:** PASS ✓ — verified by running a transparent batch **from `/tmp`** (results landed in
  `<engine>/results/…_20260625-160921/`, no nested junk), `make tps ARGS="list"` from root, and a
  full‑shielded batch from root (native crypto intact). `ruff`: no new findings (pre‑existing `E702`
  only); both edited modules byte‑compile.
- **Files changed:** `pyproject.toml` (engine wired into **both** poetry + uv), `Makefile` (`tps`
  target), engine `config.py` + `cli.py` (anchored + timestamped results, `--results-root`), two
  scenario YAMLs, 48 files relocated via `git mv`. **No `hathor`/`hathorlib`/crypto core files
  touched.** Env repair (the `.pth` fixes) is machine‑local — see §4, not part of the commit.

---

## 1. Why we were in trouble (root cause)

The venv had editable path entries (`.pth`/finder) for `hathorlib` and `hathor_tps_bench`, but **not for
`hathor` itself** — only `hathor-0.70.0.dist-info` (metadata) existed. So `import hathor` worked **only**
by the cwd accident (Python prepends the cwd to `sys.path` for `python -m`/`-c`, but **not** for
console‑script entry points). That single asymmetry is what forced the `cd`/`PYTHONPATH` ritual and is
the same reason Pylance couldn't resolve `from hathor …`.

## 2. The flatten (`benchmarks/engine/` → `engine/`)

`tps_benchmarking/benchmarks/` only ever contained `engine/`, so it was pure noise. Moved the whole
engine up one level with `git mv` (history preserved — 48 renames). Deleted a pre‑existing **untracked
junk tree** (`engine/tps_benchmarking/benchmarks/engine/results/…`) that an earlier wrong‑cwd run had
created. Updated all **live** references to the old deep path (config default, scenarios, scripts,
spikes, README, one bug test); **historical CP/planning docs keep the old path** as point‑in‑time
records (consistent with how CP‑1..9 retain old workload names).

## 3. Run from root, for **both** managers

Mirrored the existing `hathorlib`/`htr-lib` local‑editable pattern so the engine is a first‑class member
of hathor‑core's env under poetry **and** uv:

```toml
# [dependency-groups].dev            (uv / PEP 735)
    "hathor-tps-bench",
# [tool.poetry.group.dev.dependencies]
hathor-tps-bench = {path = "tps_benchmarking/engine", develop = true}
# [tool.uv.sources]
hathor-tps-bench = { path = "tps_benchmarking/engine", editable = true }
```

`Makefile` gains a root‑level target (defaults to poetry; override `RUN="uv run"`):

```make
RUN ?= poetry run
tps:
	$(RUN) hathor-tps-bench $(ARGS)
```

> **⚠️ Lockfiles NOT re‑locked (deliberate).** Adding the engine to the pyproject does **not** rewrite
> `poetry.lock`/`uv.lock` here. A full re‑lock can rebuild the `rocksdb` git dependency and disturb the
> hand‑built (maturin) `hathor_ct_crypto` module — the one part of the env that's expensive to
> reproduce. The declarative entries take effect on the **next deliberate** `poetry install` / `uv sync`
> on a clean machine; the current working venv is left untouched. Re‑locking is a future, intentional
> step (expect a `make build-shielded-crypto` afterward).

## 4. Env repair (machine‑local, not committed)

To make the *current* venv cwd‑independent **without** a re‑lock, two surgical one‑line `.pth` files were
written into site‑packages (touching only path resolution — never rocksdb or crypto):

- `hathor.pth` → the repo root (restores the missing `hathor` / `hathor_cli` / `hathor_tests` entry)
- `hathor_tps_bench.pth` → `tps_benchmarking/engine` (re‑points the engine editable after the move; the
  stale setuptools finder that mapped the **old** path was removed)

These live in the venv, not the repo, so they're not in this commit; a clean `poetry install` / `uv sync`
regenerates the equivalent entries from §3.

## 5. Timestamped, anchored results

- `config.py`: `results_root` now defaults to `DEFAULT_RESULTS_ROOT = <engine>/results` — **absolute,
  anchored to the package** (`Path(__file__).resolve().parents[1] / "results"`), not the cwd. This alone
  prevents the stray nested‑tree bug.
- `cli.py`: a single `_new_run_dir(results_root, label)` helper appends `_YYYYMMDD-HHMMSS` (to the
  second) and `mkdir`s; all three sites (`run`, `sweep`, `multibatch`) use it. Added a `--results-root`
  override (on `run` and `sweep`). Removed the three now‑orphaned local `from pathlib import Path`.
- Scenarios `basic.yaml` / `defunct.yaml`: dropped the cwd‑relative `results_root:` override so they
  inherit the anchored default (commented example kept).

## 6. Verified

```
# from /tmp (wrong cwd on purpose):
$ hathor-tps-bench run -n 6 -w 2 -i 1 -o 2
[run] results → …/tps_benchmarking/engine/results/baseline_1-tip-transparent_N6_I1_O2_20260625-160921/
# → landed in <engine>/results (NOT /tmp); no nested junk tree created.

$ make tps ARGS="list"           → 6 tx types listed (poetry path, from root)
$ hathor-tps-bench run --full-shielded -n 4 -w 1 -i 1 -o 2 --range-proof-bits 64
[run] results → …/engine/results/baseline_full-shielded_N4_I1_O2_20260625-161117/   # crypto intact
$ ruff check cli.py config.py    → only pre-existing E702 (semicolons); no new F401/orphans
```

## 7. Next

Optimization variant goes on top of this tidy base (this is the pre‑optimization groundwork on
`tool/tps-shielded-optimized`). Optional follow‑ups: the deliberate dual re‑lock (with crypto rebuild)
when targeting a fresh machine; refresh `docs/call-tree.md` for the new path.
