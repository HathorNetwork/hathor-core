# 05 — Desktop app: packaging & distribution design

**Status:** proposed · **Date:** 2026-08-05 · **Branch:** `tool/tps-desktop-app`
**Supersedes nothing.** Follows on from the UI proof of concept in `tps_benchmarking/ui-tests/`.

---

## 1. Goal

Turn the benchmark engine + UI into a **double-clickable application** for Linux, macOS and
Windows. A non-technical user downloads an installer, runs it, picks a scenario, presses
*Simulate*, and gets figures and a spreadsheet. **No terminal, no `git clone`, no Python, no Rust
toolchain, no compiler.**

### Non-goals for this phase

- Mobile. Deferred deliberately — see §9 for the shape it should take when it happens.
- Running against mainnet, or any networked node. The app measures a local in-process node.
- Multi-user / hosted service. This is a local desktop application.

---

## 2. What actually has to ship

The UI is the easy part: framework-free HTML/CSS/JS served by a stdlib `http.server`. The payload
is a **full Hathor node with three native components**, and they set the whole packaging strategy.

| Component | Kind | Packaging difficulty |
|---|---|---|
| `hathor_ct_crypto` | Rust / pyo3 → `secp256k1-zkp` | Medium. maturin project; hand-built today, and CP‑14 records it as "expensive to reproduce" |
| `htr_lib` | Rust / pyo3 → `rocksdb 0.24`, `secp256k1` | Medium‑high. Compiles librocksdb **from source**; needs `libclang` at build time |
| `rocksdb` (python‑rocksdb) | C++ extension, **git dependency** | **Highest.** No published wheels; builds against system librocksdb; lives as editable source in `venv/src/` |

Plus: CPython pinned `>=3.11,<3.14`, matplotlib, and the node itself.

**Size.** The current dev venv is 418 MB, but that includes mypy/coverage/ruff. A production
subset will be smaller; **measure it before quoting a number**. Working assumption for planning:
**200–350 MB installed per platform**, dominated by CPython + matplotlib + the RocksDB static
library.

---

## 3. Architecture — Tauri shell + Python sidecar

```
┌─────────────────────────────────────────────────────────┐
│  Tauri shell  (Rust, ~10 MB, uses the SYSTEM webview)   │
│  · native window, menu, "open results folder"           │
│  · picks a free port, owns the sidecar's lifecycle      │
│  ┌───────────────────────────────────────────────────┐  │
│  │  webview → the EXISTING ui-tests/static/ verbatim  │  │
│  └───────────────────────────────────────────────────┘  │
│                        │ http://127.0.0.1:<ephemeral>   │
│  ┌─────────────────────▼─────────────────────────────┐  │
│  │  sidecar: frozen Python (server.py)                │  │
│  │    └─ subprocess per run: the SAME binary, --worker│  │
│  │         └─ NodeHarness → real node, RocksDB, Rust  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**Why Tauri over Electron.** Tauri uses the operating system's webview instead of bundling
Chromium: ~10 MB of shell versus ~150 MB. Next to an already-large Python payload, Electron's
overhead buys nothing. Tauri also has first-class *sidecar binary* support, which is exactly the
shape we need, and produces signed installers per platform.

**Why the UI survives untouched.** `ui-tests/static/` is plain HTML/CSS/JS with no build step and
no framework, talking to a documented HTTP API. It drops into a webview unchanged. The desktop
migration is therefore a *packaging* project, not a rewrite — which is the main reason route 4 is
cheap relative to its result.

---

## 4. Phase 0 — Wheels (prerequisite for everything)

Nothing downstream works cleanly until the native components install without a compiler. This
phase is not optional and should be done first, because it also de-risks the rest.

1. **`hathor_ct_crypto` and `htr_lib` → wheels.** Both are already maturin/pyo3 projects. Add
   `cibuildwheel` in CI over the matrix **{linux x86_64+arm64, macOS x86_64+arm64, Windows x86_64}
   × cp311–cp313**. Publish to an internal index or attach to GitHub releases.
2. **Drop `python-rocksdb`.** *(Decided 2026-08-05.)* The optimized Rust pipeline is now the
   product's only pipeline — per-optimization A/B was a Phase-3 question, it has been answered and
   published, and it is preserved on `tool/tps-shielded-optimized` plus the `pre-opt-merge` tag.
   The app therefore never needs the baseline storage backend.

   **This requires deleting nothing.** `hathor/opt_flags.py` states that `opt_enabled` returns
   **ON when the env var is absent** — so the app simply stops exporting `HATHOR_OPT_*` and the
   fully-optimized path runs. The gating sites stay in the tree, untouched, for upstream's own
   merge decision. The only work is making `import rocksdb` lazy in
   `hathor/storage/rocksdb_storage.py:20` and the four index modules, so the package is not needed
   at import time.

   **Accepted cost:** scenarios **P9** (opt vs no-opt) and **P10** (per-section isolation) can no
   longer run and are retired — see §8.6.
3. **Verify a clean-machine install** in a container with no Rust and no compiler:
   `pip install hathor-tps-bench-ui` must succeed. This is the phase's exit criterion.

---

## 5. Phase 1 — Freeze the Python side

PyInstaller **one-folder** (not one-file: one-file unpacks to a temp dir on every launch, which is
slow and confuses antivirus). Four concrete issues, all verified against the current code:

**5.1 The worker spawn breaks when frozen.** `server.py:123` runs
`[sys.executable, str(HERE / "run_sim.py"), …]`. In a frozen app `sys.executable` is the *app
binary*, not an interpreter, and `run_sim.py` does not exist as a loose file. Fix: give the bundle
a `--worker` mode so it re-invokes **itself**:

```python
cmd = ([sys.executable, "--worker", payload] if getattr(sys, "frozen", False)
       else [sys.executable, str(HERE / "run_sim.py"), payload])
```

The subprocess-per-run design must be kept — it is what isolates the process-global state
`NodeHarness` mutates — so this is a wiring change, not an architectural one.

**5.2 Results must leave the install directory.** `run_sim.py:91` writes to `HERE/"runs"`, i.e.
inside the package. That is read-only in a macOS `.app` and under Windows *Program Files*. Move to
per-OS user data directories:

| OS | Path |
|---|---|
| Windows | `%LOCALAPPDATA%\HathorTPSBench\runs\` |
| macOS | `~/Library/Application Support/HathorTPSBench/runs/` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/HathorTPSBench/runs/` |

Add a menu item and an in-UI button that opens that folder — non-technical users will not go
looking for it.

**5.3 Bundled data files.** `harness.py:16` sets `HATHOR_CONFIG_YAML` from
`hathorlib.conf.UNITTESTS_SETTINGS_FILEPATH`, a path *inside the installed package*. The YAML must
be collected into the bundle and the path resolved against `sys._MEIPASS` when frozen. Same for
matplotlib's `mpl-data` (there is a standard PyInstaller hook). `plotting.py` already forces the
`Agg` backend, which is correct for a headless sidecar and must stay.

**5.4 Ephemeral port.** The server defaults to a fixed `8765` (`server.py:228`). A desktop app must
bind port `0`, let the OS choose, and hand the resolved port to the webview — otherwise two
launches collide, or a user's unrelated service does. The existing friendly `EADDRINUSE` message
stays useful for the CLI path.

---

## 6. Phase 2 — The shell

- Tauri window loads `http://127.0.0.1:<port>` once the sidecar reports ready (poll `/api/simulations`,
  which is deliberately hathor-free and answers in milliseconds).
- **Lifecycle:** killing the window must terminate the sidecar *and* any in-flight worker
  subprocesses. An orphaned node holding a temp RocksDB is a silent resource leak.
- **First-run experience:** a short explainer — what is being measured, that figures are
  hardware-specific, roughly how long a scenario takes. The report's caveats currently live only in
  the report.
- Native menu: open results folder, view logs, about/version.

---

## 7. Phase 3 — Installers, signing, updates

| Platform | Artifact | Signing |
|---|---|---|
| Windows | `.msi` / NSIS | Authenticode; unsigned builds trip SmartScreen |
| macOS | `.dmg` | Developer ID **+ notarization**; unsigned builds are Gatekeeper-blocked |
| Linux | `.AppImage` (+ `.deb`) | none required |

**Start the certificate procurement early.** It involves an organisational identity, cost and lead
time, and it is the classic last-minute blocker on projects exactly like this one.

Tauri ships an updater; wire it once there is a release feed. Decide explicitly whether the app
phones home at all — for a benchmark distributed inside an organisation, **no telemetry by
default** is the right posture.

---

## 8. Product gaps to close before shipping

These are POC-acceptable but not ship-acceptable, and none are packaging problems:

1. **No cancel.** A shielded scenario runs minutes to hours; today it must finish or be killed.
   A shipped app needs a stop button that terminates the worker and cleans its temp DB.
2. **No resume.** `report_data` already writes a manifest that supports skipping completed cells;
   the UI ignores it and always starts a fresh run directory.
3. **No machine context.** Figures are single-thread, hardware-specific numbers. The app should
   capture CPU model, core count, RAM and OS with every run and show them beside the result,
   carrying the report's "scale by single-thread score" caveat into the UI. Without this, users
   will compare incomparable numbers — the single most likely way this tool misleads people.
4. **Run history.** Run state is in memory; restarting orphans it. A shipped app should list past
   runs from the results directory.
5. **Log suppression is a measurement switch, not a preference.** The UI already says so; the
   desktop app must keep that framing rather than burying it in a settings panel.
6. **Retire P9 and P10.** With the baseline pipeline gone they cannot run. Mark them archived
   rather than deleting them — `Scenario` already carries a `deferred` field that skips a scenario,
   so setting it keeps the definitions, the published Phase-3 results and the figure families
   traceable while removing the cards from the UI.

---

## 8b. The measurement axes that replace them

*(Decided 2026-08-05.)* Per-optimization isolation was a one-time question about PR #1729. The
tool's forward-looking purpose is **characterising the node**, so the flag surface shifts from
"which optimization" to the axes below. These are the knobs the UI should expose.

| Axis | Question | Status |
|---|---|---|
| **Transparent vs shielded** | What does confidentiality cost? | Already measurable (P1–P8, P12) |
| **Single-thread vs multi-core** | How does verification scale with workers? | **Not exposed** — see below |
| **Transaction shape** | inputs, outputs, range-proof width | Already measurable |
| **Workload composition** | mixed / transition streams | Already measurable (P11) |

**The thread-scaling axis is exposed** *(done 2026-08-05)*. `harness.py` used to hardcode
`ScriptVerificationPool(mode=RUST, num_workers=4, min_inputs=4)`. It now takes `script_mode`,
`script_workers` and `script_min_inputs`, threaded through `EnvConfig`, the CLI
(`--script-mode/--workers/--min-inputs`), and `Cell` for per-cell scenario overrides.

Two constraints discovered while wiring it, both load-bearing:

- **One rayon pool per process.** `htr-rs/crates/htr-lib/src/script/mod.rs:133` holds it in a
  `OnceLock` — *"sized on first use; later calls with a different num_workers reuse the existing
  pool"*. Since `report_data.run_cell` drives every cell and repetition in **one** process, a
  worker sweep written as sibling cells would run every point at the first cell's thread count and
  draw a flat line that reads as *"threads don't help"*. `harness._check_rayon_pool_reuse` now
  **raises** on a conflicting second value: a sweep must be one process per point.
- **Only `disabled`, `rust` and `shadow-rust` work here.** `threads`/`processes` hand jobs to the
  Python opcode interpreter through `DetachedUtxoScriptExtras`, which this branch never wired —
  its own docstring says so, and selecting them dies in `OP_CHECKSIG` with
  `AttributeError: … has no attribute 'tx'`. `SCRIPT_MODES` therefore offers three modes rather
  than five; the multi-core axis is `rust` + `--workers`.

**Finding 1 — the Rust batch call is worth ~5.4× on its own.** Transparent, N=200, I=8:

| config | S3S4 wall | tx/s |
|---|--:|--:|
| `--script-mode disabled` (serial Python) | 4 929 µs | 175 |
| `--script-mode rust --workers 1` | **913 µs** | **668** |

That is where the S3S4 win lives — a *single* rayon worker already captures it. The gain is the
batched, GIL-released Rust call, not the parallelism.

**Finding 2 — parallel scaling peaks at PHYSICAL core count, then collapses.** Transparent,
N=80, one process per point; `rayon CPU/tx` is read per-thread from `/proc/self/task` for the
`script-verify-*` threads only, so it excludes RocksDB's background work:

| workers | I=8 wall | I=8 rayon CPU | I=8 tx/s | I=32 wall | I=32 rayon CPU | I=32 tx/s |
|---|--:|--:|--:|--:|--:|--:|
| 1 | 1 723 µs | 375 µs | 304 | 3 437 µs | 1 500 µs | 199 |
| 2 | 1 464 µs | 625 µs | 396 | 2 780 µs | 1 625 µs | 236 |
| **4** | **1 392 µs** | 625 µs | **413** | **2 638 µs** | 2 375 µs | 232 |
| 8 | 2 864 µs | 1 750 µs | 208 | 2 907 µs | 3 625 µs | 221 |

The reference machine is an **i5‑11300H: 4 physical cores / 8 logical threads**. Fan-out helps to
**4 workers** (wall −19 % at I=8, −23 % at I=32) and then **reverses hard at 8**, because rayon
then claims every logical core while the process still needs the single-threaded driver (S1/S2/S5/S6)
and RocksDB's compaction threads. Rayon's work-stealing threads also **spin before sleeping**, which
is visible as rayon CPU/tx nearly doubling from 1→2 workers *while wall time improves* — that extra
CPU is spin, not work.

> **Verification, not inference.** Thread identity was confirmed directly: `/proc/self/task` shows
> exactly 1/2/4/8 threads named `script-verify-*` matching `--workers`. An earlier reading of this
> axis inferred parallelism from `process_time_ns` exceeding wall — that is unsound, because
> `process_time_ns` also counts RocksDB background threads, and it led to the wrong conclusion that
> fan-out never helps. Per-thread `/proc` accounting is the correct probe.

**⚠️ Not report-grade — and the 1→4 gain did NOT reproduce.** Each point above is a single run on
a host with ±25 % run-to-run noise. A later single run of the same axis (I=8, N=80) gave
**1 worker → 705 tx/s vs 4 workers → 594 tx/s**, i.e. the reverse ordering. Standing conclusions:

| claim | status |
|---|---|
| Rust batch call ≫ serial Python (~5×) | **solid** — 5× exceeds any plausible noise |
| 8 workers (= logical cores) is much worse than 4 | **solid** — ~2×, reproduced at I=8 and I=32 |
| 4 workers beats 1 | **unconfirmed** — reversed on a repeat; within noise |

So the axis is *exposed and correct*, but its shape below the oversubscription cliff is not yet
known. A proper answer needs k ≥ 3 interleaved runs per point, and that is the first experiment to
run once the tool is otherwise settled.

**Finding 3 — why more workers barely moves TPS: only ~25 % of the budget is parallelisable.**
Decomposed at I=8, 1 worker, by timing inside `ScriptVerificationPool.run_jobs`:

| slice | µs/tx | nature |
|---|--:|---|
| total per tx | 1 498 | |
| S3S4 verify | 910 | 61 % of total |
| └ inside the pool call | **375** | **the only fan-out-able work** |
| └ rest of S3S4 | 535 | serial: PoW, sigops, sighash, one RocksDB read **per input**, balance, merge |
| S1+S2+S5+S6 | 588 | serial by design — the driver runs one tx at a time |

The resulting Amdahl ceiling, with the in-pool share measured by `perf_counter_ns` (an upper bound,
since it includes serial FFI marshalling):

| inputs | in-pool share | max @4 workers | max @∞ |
|--:|--:|--:|--:|
| 2 | 15 % | 1.13× | 1.18× |
| 8 | 25 % | **1.23×** | 1.33× |
| 32 | 38 % | 1.40× | 1.63× |

**At I=8 the entire theoretical gain is +23 % against a ±25 % noise floor** — which fully explains
why repeated sweeps disagreed. The sweeps were not faulty; the effect is below the measurement
error. Two further drags: FFI marshalling inside the pool call is serial (375 µs wall vs ~333 µs
rayon CPU), and idle rayon workers spin (rayon CPU rises 375 → 875 µs for identical work going 1 → 8
workers), which is what turns oversubscription into the one clearly-measurable effect.

The structural reason the share stays low: **each extra input adds parallel work AND serial work** —
one more ECDSA (~42 µs, fan-out-able) but also one more storage read for the spent output plus its
sighash contribution, both serial in the driver thread.

> **Consequences for the showcase.** (a) At the canonical **1i2o** shape the worker count is
> effectively irrelevant — the axis only matters for consolidation-style, many-input transactions.
> (b) "Single-thread vs multi-core" for *transparent* traffic is therefore not a scaling-curve
> story but a story about **how little of node processing is parallelisable at all**; the real
> levers are the serial ~75 % (consensus, storage, per-input reads). (c) **Shielded is where
> multi-core would actually pay** — its cost is ~90 % verification, so its parallelisable fraction
> is far higher, which raises the priority of fixing the serial shielded verification path above.

**Finding 4 — what the Rust merge actually bought: serial speed, not parallelism.**

This matters because it is easy to describe PR #1729 as "the parallelization PR". Its own measured
ladder does not support that:

| stage | TPS | |
|---|--:|---|
| pure-Python service | 980 | |
| Rust verifiers, no batching | 1 064 | |
| two-call batching | 1 161 | |
| single fused call | 1 559 | **all verification ends here — 1.59×** |
| … Phase A, save dedup, binary metadata, indexes, tips … | **3 649** | **a further 2.34×, all consensus/storage** |

So **consensus/storage contributed more than verification did** (2.34× vs 1.59×) — which is what our
own P10 found independently. And *within* verification, the PR's S3S4 analysis records the win at
**one input** — where parallelism is impossible by definition — as already **10.9×** versus Python,
"because it's one GIL-released rayon batch over `libsecp256k1`". The mechanism is **native code +
GIL release + amortised FFI**, not fan-out.

**Three distinct senses of "parallel", and where each stands here:**

| sense | status | effect measured |
|---|---|---|
| across the **inputs of one tx** (rayon pool) | **merged, on by default** | real but ≤1.23× at I=8; below the noise floor |
| across **txs in a sync batch** (fused pipeline) | implemented, **opt-in, off** | **0.97×** — see below |
| across **transactions in the pipeline** | **not in this PR, and not possible** | consensus is inherently sequential |

The batch pipeline was deferred on the grounds that a per-tx driver never assembles a batch
(`discussions/optimization-analysis/deferred-sync-path-fused-pipeline.md`). Running it anyway
(`scripts/sync_precompute_experiment.py`, N=300, I=3) confirms the reasoning:

```
precompute actually ran (stash populated): True
stored-state identical (sync vs standard):  True
standard per-tx : 702 tx/s      sync precompute : 682 tx/s      ratio 0.97x
```

Even with the batch pipeline active and verified to have run, there is **no gain** — consistent with
Finding 3, because batching does not change how much of the budget is parallelisable.

> **Careful with the wording.** It is wrong to say "the merged code parallelises nothing" — it
> demonstrably does (1/2/4/8 `script-verify-*` OS threads, whose own CPU rises with worker count).
> The accurate statement is: **it parallelises real work, but that work is a minority of the
> per-transaction budget, so the parallelism contributes little on this path.** What is genuinely
> absent is cross-transaction parallelism, which this PR never attempted.

**Parked — range proofs wider than 64 bits (limb decomposition).** `libsecp256k1-zkp` caps
Borromean range proofs at 64 bits *in the C API* (`uint64_t value`, `min_bits … - 64`), so widening
our Rust types would change nothing — 65/82/96/128 all fail at **creation**, inside the library.
A wider range is reachable by decomposing the value: commit `v = v_lo + 2^64·v_hi` as `C_lo`/`C_hi`,
range-prove each limb over `[0, 2^64)`, and have the verifier also check `C == C_lo + 2^64·C_hi`.
That point equation is mandatory — without it the limbs are unrelated to the committed value, and
two in-range numbers prove nothing about `C`. Cost: ~2× proof bytes (~10 KB/output), ~2×
verification, plus a wire-format and balance-equation change.

Not built, for two reasons: every Hathor amount is `u64` end to end, so no value can need it; and
for benchmarking, "two proofs plus a point check" costs about what **two outputs** cost, which `-o`
already measures. If magnitude (not precision) is ever the goal, the C API's base-10 `exp`
parameter extends it natively and makes proofs *smaller* — though the same header notes values must
stay in `[0, 2^63)` once `exp` is non-zero, so 2^64 remains the hard boundary either way.

**Still unmeasured:** a **true block-sync workload** — vertices arriving dependency-ordered from the
network rather than a synthetic batch on the per-tx driver. That is the one remaining place batch
parallelism could pay, and building it is the natural companion to the axes in this section.

**Finding 5 — three stacked serialisations, and only the third is binding.**

A natural question is whether the benchmark *creates* the serial behaviour by feeding one
transaction at a time. It partly does — but that is not the constraint that matters:

| # | Serialisation | Ours? | Removable? |
|---|---|---|---|
| 1 | Driver loop: one tx fully through S1→S6, then the next (`driver/runner.py`) | yes, by design | yes |
| 2 | Workload: `tx{t} --> tx{t-1}` (`workload/transparent.py:285`) — a linear parent chain, so `tx_k` cannot validate before `tx_{k-1}` is stored | yes, a side-effect of the 1-tip fix for O(N²) tips | yes (k-tip mesh) |
| 3 | **The node applies vertices synchronously on the reactor thread** | **no** | **not today** |

For (3): there is no `Lock`, no `threading`, no `deferToThread` anywhere in `vertex_handler.py` or
`consensus.py`, and the save/consensus entry point is named **`_unsafe_save_and_run_consensus`** —
"unsafe" meaning *unsynchronised*, i.e. it assumes a serialised caller. Consensus mutates shared
state (tips index, storage, metadata, voided flags) with no concurrency control. **Submitting
transactions differently therefore cannot unlock cross-transaction parallelism: the capability does
not exist.** The 0.97× sync-precompute result is the empirical confirmation — batching the
parallelisable part changes nothing while the serial part is untouched.

Consequences, in priority order:

1. **The workload should still be fixed.** The 1-tip chain is *maximally* serial; mainnet is a 2–3
   tip mesh whose transactions parent recent tips rather than each other, and are therefore mostly
   independent. Our workload is not merely unrepresentative — it is the worst case for anything
   parallel. This is a second, stronger argument for the k-tip workload already on the list.
2. **The driver is not the place to start.** While consensus is single-threaded, a batch-submitting
   driver buys only what the fused pipeline already buys.
3. **Shielded is the real unlock**, and it converges on the fix flagged above: shielded cost is
   ~90 % verification and embarrassingly parallel (N independent range proofs per tx), so it is the
   one regime where the parallelisable fraction is large enough for fan-out to dominate — and it is
   blocked solely by shielded transactions taking the serial verification path
   (`transaction_verifier.py:102`, `:276-279`).

**What this means for the default.** `script_workers` now auto-sizes to **physical cores**. That is
a *risk-managed* default, not an empirically-optimal one: the only strong evidence is that sizing to
*logical* cores hurts badly, so physical cores is the safe side of the one cliff we have actually
measured. Whether the true optimum is 1, 2 or physical-cores remains open — which is precisely the
kind of question the fleet idea (§9) is well suited to answer, since it needs many machines.

> **⚠️ Note for the future — shielded verification is still serial.** The Rust/parallel script
> pool applies to **transparent** input verification only; any transaction spending or creating a
> shielded output falls back to a serial path (`hathor/verification/transaction_verifier.py:102`
> and `:276-279`), and the range-proof / surjection crypto is single-threaded per proof regardless.
> Since shielded cost is ~90 % verification and scales with **output count**, this is the single
> largest remaining lever for shielded throughput — an embarrassingly-parallel workload (N
> independent proofs per transaction) that neither the base implementation nor PR #1729 exploits.
>
> **Consequence for the thread-scaling axis:** until this is fixed, a `workers` sweep will show
> scaling for transparent transactions and a **flat line for shielded ones**. That is a real
> finding worth plotting, not a bug — but it must be labelled, or it reads as a broken experiment.
> Root cause and proposed fix are written up in
> `discussions/optimization-analysis/REVISIT-shielded-steps-without-opt-benefit.md`.

---

## 9. Later — fleet orchestration and the mobile client

Captured now because it shapes decisions made earlier.

The idea: a **mobile app that dispatches runs to laptops and other machines on the network and
aggregates their results into one dashboard**. This is the right mobile story, and it sidesteps the
reason a phone cannot run the benchmark itself — a thermally-throttled, big.LITTLE-scheduled phone
number tells you nothing about a full node, and this project's entire methodology is "scale by
single-thread CPU performance".

Sketch:

```
  mobile / web dashboard  ──▶  coordinator  ──▶  agent on machine A (desktop app, headless mode)
                                           ├──▶  agent on machine B
                                           └──▶  agent on machine C
                              aggregates results + machine specs per host
```

Two properties of the current design already point this way and should be **preserved**:

- The worker speaks a **line-delimited JSON protocol** (`@@TPSUI@@`) over stdout — already a
  machine-readable progress/result stream, which is what an agent would forward.
- Results are written in the **report-data layout** (`<P>/<cell>.band.csv` + `.meta.json` +
  `manifest.json`), so a coordinator can aggregate across hosts with `report_plots.py` unchanged.

The natural enabler is a `--headless` / `--agent` flag on the same binary shipped in Phase 1: one
artifact serves both the desktop app and a fleet node. **Because per-host machine specs are what
make cross-machine comparison meaningful, item 8.3 is a prerequisite for this, not an extra.**

---

## 10. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| macOS/Windows Rust builds harder than expected | Blocks Phase 0 | Prototype the cibuildwheel matrix **first** — cheapest way to learn this |
| ~~Dropping python-rocksdb costs P9/P10~~ | — | **Resolved 2026-08-05**: accepted; P9/P10 retired (§4.2, §8.6) |
| Thread-scaling sweep looks broken on shielded | Misread as a bug | Label the flat line; it is the serial-verification finding (§8b) |
| Bundle size 300 MB+ | Distribution friction | Measure a production-only venv; strip dev deps; consider per-platform trimming |
| Code signing lead time | Blocks release | Start procurement in parallel with Phase 0 |
| Users compare numbers across machines | **Misleading results** | §8.3 machine capture, plus in-UI caveats |
| Shipping a full node inside a desktop app | Support expectations | Decide versioning/support posture explicitly before external distribution |

---

## 11. Sequencing

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **0** | Wheels for both Rust crates; python-rocksdb decision | `pip install` succeeds on a clean machine with no compiler |
| **0.5** | `uv tool install` / pipx distribution | Colleagues can run it without a clone — an early, cheap stopgap |
| **1** | Frozen Python sidecar (§5.1–5.4) | The frozen bundle runs a scenario end to end |
| **2** | Tauri shell | Double-click launches; window close leaves no orphan process |
| **3** | Signed installers for three platforms | A non-technical user installs and runs a scenario unaided |
| **4** | Product gaps (§8) | Cancel, resume, machine specs, run history |
| **later** | Fleet agent + mobile dashboard (§9) | — |

Phase 0 is the long pole and the one with genuine unknowns. Everything after it is largely
mechanical.
