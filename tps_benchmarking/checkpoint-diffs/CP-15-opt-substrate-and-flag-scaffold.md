# Checkpoint CP‑15 — optimization merge: Rust substrate + `--opt`/`--no-opt` flag scaffold

- **Snapshot A:** end of CP‑14 (`c667b92e`) — shielded benchmark engine, refactored to run from root.
  No optimization code; `htr-lib` was a maturin stub (`sum_as_string` only).
- **Snapshot B:** the optimized `htr-lib` Rust crate from PR #1729 is vendored and built into the venv
  (full surface: `verify_tx_from_bytes`, `RocksDb`, `metadata_to_bytes`, `parse_vertex`, …), and a
  per‑section optimization‑gating **flag scaffold** (`--opt`/`--no-opt` + `s1 s2 s3s4 s5 s6`) is wired
  through the CLI → config → harness. **No optimization behavior is gated yet** — flags resolve,
  print, and thread through; every code path still runs the pre‑existing default.
- **Status:** PASS ✓ — `htr_lib` imports the full surface; `resolve_opt` verified against the locked
  semantics; a tiny run with `--no-opt s3s4` prints the correct map and completes; the three error
  guards (both masters / standalone section / unknown section) all reject correctly.
- **Files changed:** vendored `htr-rs/crates/htr-lib/` (7 new module dirs + `Cargo.toml`/`Cargo.lock`/
  `lib.rs`/`htr_lib.pyi`); engine `config.py`, `cli.py`, `node/harness.py`. Steps 1–3 of the gated
  merge. Safety tag `pre-opt-merge` @ `c667b92e`.

---

## 1. Why / context

This is the first checkpoint of the **gated merge** of the PR #1729 optimizations (analyzed in
`discussions/optimization-analysis/`). Strategy (locked 2026‑06‑26): **append both implementations**
(baseline + optimized) and let a runtime flag pick the live one per section, optimized = default‑ON.
This checkpoint lands the non‑conflicting foundation — the Rust crate and the flag plumbing — *before*
any consensus‑critical wiring, so the risky work has a verified base.

## 2. Rust substrate (Steps 1–2)

The optimized `htr-lib` crate is entirely new code on top of our stub, so it landed cleanly:
- The `htr-rs/Cargo.toml` workspace manifest is **byte‑identical** both sides — untouched.
- Copied the 7 new module dirs (`script/ verify/ pipeline/ storage/ metadata/ static_meta/ vertex/`),
  the new `lib.rs`, the dependency‑bearing `Cargo.toml` (adds `rayon`/`ripemd`/`rocksdb`/`secp256k1`/
  `sha2`), `htr_lib.pyi`, and the resolved `Cargo.lock`.
- **The new `lib.rs` keeps `sum_as_string`**, and the upstream `manager.py` keeps its temporary
  `htr_lib.sum_as_string` assertion — so our `manager.py:255-257` scaffold check still passes and **no
  Python was touched** for the substrate.
- **Build requirement discovered:** `librocksdb-sys` runs `bindgen`, which needs `libclang.so` (only
  `libclang-cpp` was present). Installing `libclang-dev` (llvm‑14) unblocks it. Build command:
  `poetry run maturin develop --release -m htr-rs/crates/htr-lib/Cargo.toml` (compiles librocksdb from
  source — a few minutes).

## 3. Flag scaffold (Step 3) — zero behavior change

- `config.py`: `OPT_SECTIONS = (s1, s2, s3s4, s5, s6)`, `resolve_opt(opt, no_opt)` (the locked
  opt‑in/opt‑out resolver), and a `RootConfig.opt` field (default all‑ON).
- `cli.py`: `_add_opt_flags` adds `--opt`/`--no-opt` as a **mutually‑exclusive** group with
  `nargs='*'`, `choices=OPT_SECTIONS` — section names are *arguments of a master*, so a section can
  never be passed standalone. Resolved in `_apply_overrides`; an `[opt] s1=on …` status line is
  printed; `cfg.opt` is threaded into `NodeHarness(opt=…)`.
- `node/harness.py`: stores `self.opt` and carries a **TODO map** of each section → its Step‑4 wiring
  point, plus the future per‑optimization sub‑flag TODOs (esp. S5: `--mem-tips`/`--save-dedup`/…,
  S3S4: `--rust-scripts` vs `--parallel-scripts`).

## 4. Gating semantics (locked)

| Invocation | Result |
|---|---|
| *(none)* / `--opt` | all sections optimized |
| `--no-opt` | all baseline |
| `--opt s1 s5` | ONLY s1,s5 optimized (rest baseline) |
| `--no-opt s3s4` | ONLY s3s4 baseline (rest optimized) |
| `--opt`+`--no-opt`, standalone section, unknown section | error |

## 5. Verified

```
$ maturin develop --release …        → Installed htr-lib-0.1.0 (full surface imports from /tmp)
$ resolve_opt(['s1','s5'],None)      → {s1:T, s2:F, s3s4:F, s5:T, s6:F}    (and all other cases)
$ hathor-tps-bench run -n4 -w1 --no-opt s3s4
  [opt] s1=on s2=on s3s4=off s5=on s6=on … accepted 4/4
$ … --opt --no-opt   → error: not allowed with argument --opt
$ … run s3s4         → error: unrecognized arguments: s3s4
$ … --opt s9         → error: invalid choice: 's9'
```

## 6. Next (Step 4 — gating, simplest→hardest)

`s1` (parser dispatcher) → `s6` → `s2` → `s5-consensus` → `s5-storage/serde` → `s3s4`, weaving in the
shielded reconciliation (Step 5: optimizations win; the 3 shielded bug fixes stay unconditional).
Mechanism: the harness exports `HATHOR_OPT_<SECTION>` env vars from `self.opt`; gated sites in
hathor‑core read them via a small `opt_enabled()` helper. Checkpoint again **before s5‑storage and
s3s4** (the heaviest/riskiest).
