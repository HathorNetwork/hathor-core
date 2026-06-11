#!/usr/bin/env python
"""Profile the CPU cost of adding a new block to the tip (no reorg).

It builds, with the DAG Builder, a chain of blocks plus one or more groups of
mempool transactions. Each profiled block extends the current best tip (so it
never causes a reorg) and confirms a customizable number of transactions.

The profiled ``on_new_tx()`` path covers deserialization (optional), block
verification, consensus (which confirms the transactions in the block's past)
and index update.

Examples:

    # one block confirming 10 transactions
    python tools/cpu_profiling/profile_new_block.py --txs 10

    # average over 20 blocks, each confirming 10 txs and extending the previous tip
    python tools/cpu_profiling/profile_new_block.py --txs 10 --blocks 20

    # dump raw stats for profiles/cprof2pdf
    python tools/cpu_profiling/profile_new_block.py --txs 50 --output /tmp/block.prof
"""

from __future__ import annotations

import argparse

from _common import (
    add_common_args,
    build_manager,
    get_dag_builder,
    join_lines,
    profile_on_new_tx,
    reward_lock_blocks,
)


def build_block_dag(*, num_txs: int, num_blocks_to_profile: int) -> tuple[str, set[str]]:
    """Build the DAG description for `num_blocks_to_profile` tip blocks.

    The profiled blocks ``x1..xR`` are a blockchain extending the base chain tip
    (so each new block extends the current best block and never causes a reorg).
    For each profiled block ``xR``:
      - a fresh group of ``num_txs`` mempool transactions is created, linked as a
        confirmation chain (``gR_t0 <-- gR_t1 <-- ... <-- gR_t{n-1}``); they are
        independent 1-HTR txs (funded by `dummy`), linked only by parent edges so a
        single block tip confirms all of them;
      - ``xR`` confirms the chain tip, so it confirms exactly ``num_txs`` txs.

    Returns the DAG description and the set of target (block) node names to profile.
    """
    assert num_txs >= 1 and num_blocks_to_profile >= 1

    # Enough base blocks so the genesis reward spent by the `dummy` tx is unlocked.
    base_blocks = reward_lock_blocks() + 2
    r_count = num_blocks_to_profile

    lines = [
        f'blockchain genesis b[1..{base_blocks}]',
        f'blockchain b{base_blocks} x[1..{r_count}]   # the profiled tip blocks',
        # Reward-lock the dummy after b{base-1} and let the last base block confirm
        # it, so the profiled tip blocks confirm exactly `num_txs` transactions each
        # (otherwise the first one would also confirm the shared dummy funding tx).
        f'b{base_blocks - 1} < dummy',
        f'b{base_blocks} --> dummy',
        '',
    ]
    targets: set[str] = {f'x{r}' for r in range(1, r_count + 1)}
    for r in range(r_count):
        block = f'x{r + 1}'
        prev_tx: str | None = None
        for i in range(num_txs):
            tx = f'g{r}_t{i}'
            if prev_tx is not None:
                lines.append(f'{prev_tx} <-- {tx}')
            prev_tx = tx
        assert prev_tx is not None
        lines.append(f'{block} --> {prev_tx}   # confirm the chain of {num_txs} tx(s)')
        lines.append('')

    return join_lines(lines), targets


def main() -> None:
    parser = argparse.ArgumentParser(description='Profile the CPU cost of adding a new block to the tip.')
    parser.add_argument('--txs', type=int, default=10,
                        help='number of transactions confirmed by each block (default: 10)')
    parser.add_argument('--blocks', type=int, default=1,
                        help='number of tip blocks to add/average over (default: 1)')
    add_common_args(parser)
    args = parser.parse_args()

    dag_str, targets = build_block_dag(num_txs=args.txs, num_blocks_to_profile=args.blocks)

    print(f'Building DAG: {args.blocks} tip block(s), each confirming {args.txs} tx(s)')

    manager = build_manager(seed=args.seed)
    artifacts = get_dag_builder(manager).build_from_str(dag_str)

    profiled = profile_on_new_tx(
        manager,
        artifacts,
        is_target=lambda name: name in targets,
        output=args.output,
        sort=args.sort,
        limit=args.limit,
        include_deserialization=not args.no_deserialization,
    )

    # Report how many transactions each profiled block actually confirmed.
    print()
    for name, block in profiled:
        confirmed = sum(
            1 for _, vertex in artifacts.list
            if vertex.is_transaction and vertex.get_metadata().first_block == block.hash
        )
        print(f'  {name}: confirmed {confirmed} transaction(s)')


if __name__ == '__main__':
    main()
