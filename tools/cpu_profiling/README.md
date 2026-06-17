# CPU profiling: adding a new transaction / block

Two standalone scripts that profile the CPU cost of the full vertex-addition
pipeline (`HathorManager.on_new_tx()` → deserialization, verification, consensus
and index update) using the DAG Builder to create realistic scenarios.

Both bootstrap an in-memory node (the same setup the DAG Builder unit tests use)
and run under `cProfile`. They print a `pstats` table and, optionally, dump the
raw stats for visualization.

Run them with `uv`:

```bash
uv run python tools/cpu_profiling/profile_new_tx.py    [options]
uv run python tools/cpu_profiling/profile_new_block.py [options]
```

## profile_new_tx.py

Profiles adding new (mempool) transactions. Each transaction spends a dedicated
funding tx, so you control the exact number of inputs and outputs.

| flag | meaning | default |
| --- | --- | --- |
| `--inputs N` | inputs per transaction | `1` |
| `--outputs N` | outputs per transaction | `2` |
| `--count N` | number of independent txs to add (averaged over) | `1` |
| `--output-type T` | output type (`htr`; shielded lives in a separate branch) | `htr` |

```bash
# one tx, 1 input, 2 outputs
uv run python tools/cpu_profiling/profile_new_tx.py --inputs 1 --outputs 2

# average over 50 txs, each with 10 inputs and 10 outputs
uv run python tools/cpu_profiling/profile_new_tx.py --inputs 10 --outputs 10 --count 50
```

## profile_new_block.py

Profiles adding a block to the tip (extends the current best block, never causes
a reorg). You control how many transactions each block confirms.

| flag | meaning | default |
| --- | --- | --- |
| `--txs N` | transactions confirmed by each block | `10` |
| `--blocks N` | number of tip blocks to add (averaged over) | `1` |

```bash
# one block confirming 10 transactions
uv run python tools/cpu_profiling/profile_new_block.py --txs 10

# average over 20 blocks, each confirming 50 txs and extending the previous tip
uv run python tools/cpu_profiling/profile_new_block.py --txs 50 --blocks 20
```

## Common flags

| flag | meaning | default |
| --- | --- | --- |
| `--count` / `--blocks` | repeat to get a stable per-call average | `1` |
| `--no-deserialization` | profile `on_new_tx()` only (skip deserialization) | off |
| `--sort KEY` | `pstats` sort key (`tottime`, `cumulative`, ...) | `tottime` |
| `--limit N` | rows in the stats table | `40` |
| `--output PATH` | dump raw `cProfile` stats to a `.prof` file | none |
| `--seed N` | RNG seed for the node | `1234` |

By default the deserialization cost is measured **inside** the profiled region,
matching the real p2p receive path (`parser.deserialize(bytes)` →
`vertex.storage = tx_storage` → `on_new_tx`). PoW verification is skipped (the
simulator verifiers), since it is negligible and the synthetic vertices are not
actually mined; every other verification step is real.

A dumped `.prof` file can be turned into a call graph with the existing helper:

```bash
profiles/cprof2pdf /tmp/tx.prof      # produces /tmp/tx.prof.dot.pdf
```

## Extending with shielded outputs

`profile_new_tx.py` has an `--output-type` hook (currently only `htr`). When the
shielded-outputs branch is merged, add the new type to `OUTPUT_TYPES` and emit the
corresponding shielded-output declarations in `build_tx_dag()`.
