N_BLOCKS=1000
CACHE_SIZE=100000
TESTNET_DATA_DIR=server-data
TCP_PORT=40403
AWAIT_INIT_DELAY=10
N_RUNS=2
BENCH_FILE=bench_results.json
BENCH_DATA_DIR=bench-data

BLUE='\033[0;34m'
NO_COLOR='\033[0m'

echo "${BLUE}Downloading testnet data...${NO_COLOR}"
mkdir $TESTNET_DATA_DIR
poetry run hathor-cli quick_test --testnet --data $TESTNET_DATA_DIR --quit-after-n-blocks $N_BLOCKS > /dev/null 2>&1

echo "${BLUE}Running server node in the background...${NO_COLOR}"
poetry run hathor-cli run_node \
  --testnet \
  --data $TESTNET_DATA_DIR \
  --cache \
  --cache-size $CACHE_SIZE \
  --x-localhost-only \
  --listen tcp:$TCP_PORT \
  &

# Await initialization
sleep $AWAIT_INIT_DELAY

echo "${BLUE}Running benchmark...${NO_COLOR}"
hyperfine \
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
