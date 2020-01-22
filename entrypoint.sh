#!/bin/sh

python -m hathor run_merged_mining --port 8082 --hathor-stratum ${HATHOR_BC} --bitcoin-rpc http://${BTC_RPC_USER}:${BTC_RPC_PASS}@${BTC_RPC}:${BTC_RPC_PORT} --hathor-address ${HATHOR_WALLET}