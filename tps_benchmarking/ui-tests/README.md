# TPS benchmark UI — proof of concept

A local browser UI for running the benchmark engine, for people who should not have to learn
`hathor-tps-bench`'s flags. **This is a POC to try, not a pipeline component**: single user,
localhost, no auth, run state in memory.

## Run it

From the hathor-core repo root:

```bash
poetry run python tps_benchmarking/ui-tests/server.py
```

It opens <http://127.0.0.1:8765/>. Flags: `--port`, `--host`, `--no-browser`.

## What's wired

**13 cards**, in two families:

**Custom run** — free-form exploration: any workload (`1-tip-transparent`,
`capless-full-shielded`, `amount-shielded`, `full-shielded`, `defunct`), any I/O shape, any
optimization map. One cell, one rep. Rendered with `plotting.py` — dark figures that match the UI.

**P1–P12** — the report scenarios, **generated from `report_scenarios.SCENARIOS`** rather than
restated, so the cards can never drift from the matrix the report was built on. Each runs its cells
on fresh nodes via `report_data.run_cell` and renders figures with `report_plots.render_scenario` —
*the report's own figures*, not a second implementation. Those are light-themed, so the UI puts
them on a light surface rather than restyling them.

Per-card knobs are exactly the three overrides `report_data` supports (N / warm-up / k) plus
range-proof width and the optimization map — **except where those are the experiment**: P9/P10 own
the optimization map and P12 owns the range-proof width, so those cards omit the corresponding
control instead of letting you contradict the experiment.

### Output

| Path | What |
|---|---|
| **custom** `tps_over_time.png`, `stage_breakdown.png` | dark, UI-native figures |
| **custom** `results.xlsx` | Summary · Stages · Configuration · Per-transaction |
| **scenario** `<P>/<cell>.band.csv`, `<cell>.meta.json`, `manifest.json` | the standard report-data layout — readable by `report_plots.py` directly |
| **scenario** `<P>/plots/*.png` + `*.pdf` | the report figures, PNG **and** vector PDF |
| **scenario** `results.xlsx` | Headline (one row per cell) · Stages · Configuration · Segments (P11) |
| **scenario** `summary.md` | the report-style markdown summary |

Scenario runs already emit vector PDF alongside every PNG.

### While a run is going

Under the progress bar the panel states exactly where it is:

```
Measuring                                          420 / 500 tx
P8 · Shielded surjection grid   ·   Cell 6/9 (4i8o)   ·   Repetition 2/3
```

The cell counter tracks the scenario's cells and the repetition counter tracks `k`, resetting at
each cell boundary. Repetition is hidden at `k = 1`, and both are dropped once the run leaves the
cells (rendering figures, writing the spreadsheet) so a finished cell is never shown as running.

### Node output

Each panel has a collapsible **Node output** console showing that run's own stdout and stderr —
the closest thing to "a terminal per node" without opening terminals. It streams incrementally
(`GET /api/run/<id>/log?since=N`, absolute line indices), keeps a 500-line ring buffer per run, and
tells the client how many lines it missed if it falls behind rather than silently renumbering.
stderr is folded in, so a worker traceback lands here too.

With log suppression on (the default) the node is fairly quiet — startup and funding at INFO,
~40 lines. Turn *Suppress node debug logging* off for the full per-transaction stream, remembering
that doing so also changes the measurement (see below).

### Defaults are sized for a person, not for the report

The report runs N=1000–5000 at k=3, which is tens of minutes to hours per scenario. The cards
default to **N=300, W=50, k=1** and show a live estimate (`9 cells × 1 rep = 9 runs, 3 150
transactions`), which turns orange for shielded work. The report values are still reachable — just
type them in.

## How it fits together

```
                        report_scenarios.py  (the P1-P12 matrix; no hathor, no reactor)
                                 │ read by both
                 ┌───────────────┴───────────────┐
browser ──GET /api/simulations──▶ simulations.py │
        ──POST /api/run────────▶ server.py       │
                                     │ subprocess│
                                     ▼           │
                                run_sim.py ──────┘
                                     │
                    custom ──▶ NodeHarness + run_batch ──▶ plotting.py ──▶ dark *.png
                  scenario ──▶ report_data.run_cell    ──▶ report_plots ──▶ report *.png + *.pdf
                                     │ on_progress
                                     │  @@TPSUI@@{json} on stdout
                                     └──▶ xlsx.py ──▶ results.xlsx
        ◀─poll GET /api/run/<id>──  status / progress / per-cell results
```

`report_scenarios.py` was split out of `report_data.py` for this: the declarative matrix (the
*what*) now imports nothing from hathor, so the web server can read it in ~15 ms, while the runner
(the *how*) still owns everything that needs a node. `report_data` re-exports every name, so
existing imports keep working.

Four deliberate choices:

- **Each run is a subprocess.** `NodeHarness` mutates process-global state (it pins
  `HATHOR_CONFIG_YAML`, initialises the global reactor, and for shielded runs rewrites the settings
  singleton). A fresh interpreter per run is the only way runs can't contaminate each other, and it
  keeps the web server free of hathor imports.
- **Progress is sentinel-prefixed JSONL.** hathor logs to stdout too, so `@@TPSUI@@` is how the
  server tells protocol from node chatter. Unprefixed lines are kept as a bounded tail for the
  error panel.
- **No new dependencies.** The venv has no flask/fastapi and no openpyxl, so the server is stdlib
  `http.server` and `xlsx.py` emits OOXML by hand. Nothing was installed into your poetry env.
- **The form is generated.** Controls are rendered from `simulations.py`; no per-flag HTML exists.

## ⚠️ The log-suppression toggle changes the numbers

This was an engine bug the UI surfaced; it is **now fixed in the engine** (`NodeHarness` configures
structlog at INFO). The toggle remains so the old behaviour is still reachable.

Nothing on the benchmark path called `structlog.configure` — that lives in `hathor_cli` — so
structlog emitted **every** level and `_post_consensus` rendered a full transaction repr per vertex.
The driver's `quiet=True` only downgrades info→debug; it does not skip the call. That render
therefore ran **inside the timed S6 stage**.

Measured N=400/W=60, 3 interleaved reps per arm (ranges non-overlapping):

| | S6 mean | total per tx | tx/s |
|---|--:|--:|--:|
| *Suppress* OFF — `--verbose-node-logs`, the old default | 226 µs | 1 960 µs | 510 |
| *Suppress* ON — the new engine default | **98 µs** | **1 792 µs** | **558** |

**Runs with the toggle ON are not comparable to the published Phase-1/Phase-3 figures**, which were
all collected with logging live. Turn it OFF to reproduce those. Per-section contribution deltas
(P10) are unaffected — logging added the same constant to both arms.

Suppression removes the render+write. A further **~46 µs/tx** remains in `_log_new_object`, which
builds its kwargs (`get_metadata`, two `datetime.fromtimestamp`, `get_feature_states`) *before*
testing the level, so that work happens even when the line is discarded. Removing it means changing
`hathor/` core — left upstream on purpose, since a production node pays it too.

## Running panels at the same time

Each run is already its **own OS process** with its own node, reactor and temporary RocksDB — start
a second panel while the first is going and you get two independent nodes. Nothing serialises them.

Output directories are `runs/<timestamp>_<sim>_<run-id>/`. The run-id is load-bearing: the
timestamp is second-resolution, so two panels started in the same second previously resolved to the
*same* directory (`mkdir(exist_ok=True)`) and the later run overwrote the earlier one's
`results.xlsx`, `summary.md` and `manifest.json` — and for a custom run its figures and `meta.json`
too, since those sit at the top level. That looked exactly like "the first panel's run was
discarded".

**On trusting concurrent numbers.** The measured path is single-threaded per run, so N concurrent
runs want N free cores. Measured here (8 logical cores, P1 N=200):

| | tx/s |
|---|---|
| 1 run | 574 … 734 (two solo runs, same config) |
| 4 concurrent | 619 · 633 · 666 · 646 |

No degradation is visible at 4-way concurrency — but the **run-to-run noise on this WSL host (±25 %)
is far larger than any contention signal**, so this shows only that contention is *below the noise
floor*, not that it is absent. Treat concurrent runs as fine for exploring, and run serially for
numbers you intend to compare or publish.

## Testing the front end

There is no browser on this machine, so a DOM bug in the result renderer shows up only as "the
figures didn't appear" — which is exactly how a `tbl.append(el('thead')).lastChild` crash shipped
(`Element.append()` returns `undefined`). `test_render.js` runs `app.js` inside a `vm` context
against a minimal DOM stub and asserts that both result shapes render the expected figures, and
that the progress text is exact:

```bash
node tps_benchmarking/ui-tests/test_render.js
```

Run it after touching `app.js`. It is a stub, not a browser — it catches structural DOM misuse and
string formatting, not layout or CSS.

## Adding a simulation

**A new report scenario** — add it to `SCENARIOS` in `engine/scripts/report_scenarios.py` and give
it a figure family in `report_plots.PLOT_SPECS`. The UI card appears on its own; nothing here
changes.

**A new free-form control** — add a `_num` / `_bool` / `_choice` entry in `simulations.py` and read
the key in `run_sim.run_custom`. The front end renders whatever the registry declares.

## Known gaps

- Run state is in memory — restarting the server orphans history (the `runs/` files survive).
- No cancel button; a long run must finish or the server be killed.
- No resume: `report_data`'s manifest is written, but the UI always starts a fresh run dir rather
  than skipping completed cells.
- Custom-run bar data-ends are square, not 4px-rounded: rounding in matplotlib data coordinates
  distorts when the x/y scales differ by orders of magnitude. Cosmetic, deferred rather than faked.
- The rendered page has not been checked in a real browser — there is no headless browser on this
  machine. The HTTP API, every scenario, and the artifacts were verified end to end.
- `runs/` is gitignored.
