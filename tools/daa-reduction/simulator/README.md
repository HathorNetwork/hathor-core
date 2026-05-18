# DAA Transition Simulation

Simulates the DAA's transient behavior when the REDUCE_DAA_TARGET feature activates, changing the target block time from 30s to 7.5s (4x faster blocks).

## Quick Start

```bash
# Run a single simulation (JSONL to stdout)
poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py --jsonl --hashpower 69905 --seed 0

# Run batch simulation (all hashpower levels x seeds -> JSON file)
poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py

# Generate charts from batch results
poetry run python tools/daa-reduction/simulator/daa_transition_charts.py

# Launch live dashboard (browser opens automatically)
poetry run python tools/daa-reduction/simulator/daa_live_server.py
```

## Files

| File | Purpose |
|------|---------|
| `daa_transition_simulation.py` | Core simulation engine (batch + JSONL modes) |
| `daa_transition_charts.py` | Offline chart generation from JSON results |
| `daa_live_server.py` | Web server: spawns simulation, streams SSE |
| `daa_live_dashboard.html` | Browser UI: live charts, controls, saved runs |
| `daa_runs/` | Auto-saved simulation results (created by web server) |
| `daa_simulation_results.json` | Batch mode output (created by batch run) |
| `daa_chart_*.png` | Generated chart images (created by chart script) |

## Simulation Modes

### JSONL Mode (Single Run)

Streams one JSON object per line to stdout. Useful for piping to other tools or for the live dashboard.

```bash
poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py --jsonl \
    --hashpower 69905 \
    --seed 0 \
    --total-blocks 1600 \
    --eval-interval 100
```

**Options:**
- `--hashpower N` : Miner hashpower in hashes/second (default: 69905)
- `--seed N` : Random seed for reproducibility (default: 0)
- `--total-blocks N` : Total blocks to mine (default: 1600)
- `--eval-interval N` : Feature activation evaluation interval (default: 100)

**JSONL event types:**

```
config       → simulation parameters
run_start    → run metadata (hashpower, seed, run_id)
phase        → phase transition (warmup, stable, signaling, locked_in, active)
block        → per-block data (height, weight, solvetime, feature_state)
run_end      → summary statistics
simulation_end
```

### Batch Mode

Runs all hashpower levels (W~21, W~30, W~40) x 10 seeds and writes results to `daa_simulation_results.json`.

```bash
poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py
poetry run python tools/daa-reduction/simulator/daa_transition_simulation.py --num-seeds 5 --total-blocks 1000
```

**Options:**
- `--total-blocks N` : Total blocks per run (default: 1600)
- `--eval-interval N` : Feature evaluation interval (default: 100)
- `--num-seeds N` : Number of random seeds per hashpower level (default: 10)

### Chart Generation

Reads `daa_simulation_results.json` and generates PNG charts:

```bash
poetry run python tools/daa-reduction/simulator/daa_transition_charts.py
```

**Generated charts:**
- `daa_chart_weight.png` - Block weight vs height (per hashrate subplot)
- `daa_chart_solvetime.png` - Solvetime vs height
- `daa_chart_cumulative_time.png` - Cumulative wall-clock time
- `daa_chart_weight_delta.png` - Weight delta from steady state (oscillation envelope)

Requires `matplotlib` and `numpy` (`pip install matplotlib numpy`).

### Live Dashboard

A web-based dashboard that runs simulations and displays results in real-time.

```bash
poetry run python tools/daa-reduction/simulator/daa_live_server.py
# Opens http://localhost:8765 in browser
```

**Features:**
- Real-time charts (weight, solvetime, cumulative time) via Chart.js
- Phase markers with color-coded annotations
- Configurable hashpower, seed, block count, eval interval
- Auto-saves completed runs to `daa_runs/`
- Load and overlay saved runs on charts

## Simulation Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| AVG_TIME_BETWEEN_BLOCKS | 30s | Pre-activation target |
| REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X | 75 (7.5s) | Post-activation target |
| BLOCK_DIFFICULTY_N_BLOCKS | 134 | DAA look-back window (mainnet value) |
| Feature signaling start | 3 * eval_interval | Height 300 (default) |
| Feature timeout | 5 * eval_interval | Height 500 (default) |
| Feature activation | 6 * eval_interval | Height 600 (default) |

### Hashpower Levels

| Label | Hashpower | Target Weight |
|-------|-----------|---------------|
| Low | 69,905 | ~21 |
| Medium | 35,791,394 | ~30 |
| High | 36,650,787,635 | ~40 |

Hashpower is calibrated as `2^W / T` where W is the target weight and T=30s.

## Simulation Phases

1. **Warmup** (height 0-268): DAA window fills with blocks, weight oscillates
2. **Stable** (height 269-299): DAA has stabilized at steady-state weight
3. **Signaling** (height 300-399): Feature activation signaling period
4. **Locked In** (height 400-599): Feature is locked in, waiting for activation height
5. **Active** (height 600+): Feature activated, DAA targets 7.5s blocks

## Key Metrics

The summary statistics include:

- **steady_weight_before/after**: Average weight before/after activation
- **weight_drop**: Expected ~2 bits (log2(30/7.5))
- **avg_solvetime_before/after**: Should be ~30s and ~7.5s respectively
- **max_solvetime_transition**: Worst-case block time during adjustment
- **convergence_blocks**: Blocks until solvetime stabilizes at new target
- **decay_triggered**: Whether weight decay (3600s gap) was activated

## Architecture

```
                    daa_transition_simulation.py
                    ├── JSONL mode (--jsonl) → stdout
                    └── Batch mode → daa_simulation_results.json
                                          │
                                          ▼
                              daa_transition_charts.py → PNGs

    daa_live_server.py ──spawns──> daa_transition_simulation.py --jsonl
         │                                    │
         │◄──────── SSE (JSONL lines) ────────┘
         │
         ▼
    daa_live_dashboard.html (browser)
```

The simulation uses the Hathor `Simulator` + `GeometricMiner` infrastructure, which simulates mining with geometric distribution for realistic block times that feed into the real DAA algorithm.
