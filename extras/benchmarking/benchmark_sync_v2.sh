hyperfine \
  --warmup 1 \
  --runs 2 \
  --command-name "normal" \
  "
    poetry run hathor-cli quick_test \
      --testnet \
      --memory-storage \
      --x-localhost-only \
      --bootstrap tcp://localhost:40403 \
      --quit-after-n-blocks 5000
  " \
  --command-name "async" \
  "
    poetry run hathor-cli quick_test \
      --testnet \
      --memory-storage \
      --x-localhost-only \
      --bootstrap tcp://localhost:40403 \
      --quit-after-n-blocks 5000 --unsafe testnet-golf --x-async-sync-v2
  " \
  --command-name "mp" \
  "
    poetry run hathor-cli quick_test \
      --testnet \
      --memory-storage \
      --x-localhost-only \
      --bootstrap tcp://localhost:40403 \
      --quit-after-n-blocks 5000 --unsafe testnet-golf --x-async-sync-v2 --x-use-multiprocessor
  "
