#!/bin/bash

N_RUNS=2
BENCH_FILE=tx_scripts_verification_results.json
N_SCRIPTS=255
N_TXS=10000

hyperfine \
  --warmup 1 \
  --runs $N_RUNS \
  --export-json $BENCH_FILE \
  --command-name "transaction scripts verification" \
  "poetry run hathor-cli bench_script_verification --n-scripts $N_SCRIPTS --n-txs $N_TXS"
