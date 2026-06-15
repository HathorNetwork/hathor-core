#!/usr/bin/env bash
# Run the UTXO transaction-processing TPS benchmark and write Bencher Metric Format JSON.
#
# Knobs come from extras/benchmarking/tps/.env (sourced by the CI workflow into the
# environment). CI uses Poetry, matching benchmark_sync_v2.sh; locally you can run the
# Python module directly under `uv run` instead.
set -euo pipefail

poetry run python extras/benchmarking/tps/bench_tps.py \
  --inputs "$INPUTS" \
  --txs "$N_TXS" \
  --blocks "$N_BLOCKS" \
  --runs "$N_RUNS" \
  --output "$BENCH_FILE"
