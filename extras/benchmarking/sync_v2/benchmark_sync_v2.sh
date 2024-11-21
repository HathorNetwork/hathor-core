hyperfine \
  --warmup 1 \
  --runs $N_RUNS \
  --export-json $BENCH_FILE \
  --command-name "sync-v2 (up to $N_BLOCKS blocks)" \
  --prepare "rm -rf $BENCH_DATA_DIR && mkdir $BENCH_DATA_DIR" \
  "
    poetry run hathor-cli quick_test \
      --testnet \
      --data $BENCH_DATA_DIR \
      --cache \
      --cache-size $CACHE_SIZE \
      --x-localhost-only \
      --bootstrap tcp://localhost:$TCP_PORT \
      --quit-after-n-blocks $N_BLOCKS
  "
