#!/usr/bin/env python
"""Profile the CPU cost of adding a new transaction to the node.

It builds, with the DAG Builder, one or more independent mempool transactions
with a customizable number of inputs and outputs, propagates everything else and
then profiles the ``on_new_tx()`` call for each transaction. The profiled path
covers deserialization (optional), verification, consensus and index update.

Examples:

    # one tx with 1 input and 2 outputs
    python tools/cpu_profiling/profile_new_tx.py --inputs 1 --outputs 2

    # average over 50 independent txs, each with 10 inputs and 10 outputs
    python tools/cpu_profiling/profile_new_tx.py --inputs 10 --outputs 10 --count 50

    # dump raw stats for profiles/cprof2pdf
    python tools/cpu_profiling/profile_new_tx.py --inputs 5 --outputs 5 --output /tmp/tx.prof
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

# Supported output types. The shielded-output type lives in a separate branch;
# wire it in here (and in `build_tx_dag`) once that code is merged.
OUTPUT_TYPES = ('htr',)


def build_tx_dag(*, num_inputs: int, num_outputs: int, count: int, output_type: str) -> tuple[str, set[str]]:
    """Build the DAG description for `count` independent transactions.

    Each transaction ``txN``:
      - spends ``num_inputs`` outputs from a dedicated funding tx ``srcN``
        (so it has exactly ``num_inputs`` inputs);
      - has exactly ``num_outputs`` outputs.

    Inputs and outputs are balanced (same total value) so the DAG Builder does not
    inject extra inputs/outputs that would change the requested counts.

    Returns the DAG description and the set of target node names to profile.
    """
    if output_type != 'htr':
        # The shielded-output type is implemented in a separate branch. When it
        # lands, emit the proper shielded-output declarations here.
        raise NotImplementedError(f'output type {output_type!r} not supported yet (supported: {OUTPUT_TYPES})')

    assert num_inputs >= 1 and num_outputs >= 1 and count >= 1
    # Inputs/outputs are limited to 255 by the (de)serialization format.
    assert num_inputs <= 255 and num_outputs <= 255

    # Enough blocks so the genesis reward spent by the `dummy` tx is unlocked.
    num_blocks = reward_lock_blocks() + 2
    # Each side sums to `total` HTR (>= max count, so the leading slot is >= 1).
    total = max(num_inputs, num_outputs)

    lines = [
        f'blockchain genesis b[1..{num_blocks}]',
        f'b{num_blocks} < dummy        # reward lock for the genesis-funded dummy tx',
    ]
    targets: set[str] = set()
    for i in range(count):
        tx = f'tx{i}'
        src = f'src{i}'
        targets.add(tx)

        # tx spends all `num_inputs` outputs of its funding tx -> num_inputs inputs.
        for j in range(num_inputs):
            lines.append(f'{src}.out[{j}] <<< {tx}')

        # funding tx output values (sum == total).
        lines.append(f'{src}.out[0] = {total - (num_inputs - 1)} HTR')
        for j in range(1, num_inputs):
            lines.append(f'{src}.out[{j}] = 1 HTR')

        # tx output values (sum == total) -> num_outputs outputs.
        lines.append(f'{tx}.out[0] = {total - (num_outputs - 1)} HTR')
        for k in range(1, num_outputs):
            lines.append(f'{tx}.out[{k}] = 1 HTR')

        lines.append('')

    return join_lines(lines), targets


def main() -> None:
    parser = argparse.ArgumentParser(description='Profile the CPU cost of adding a new transaction.')
    parser.add_argument('--inputs', type=int, default=1, help='number of inputs per transaction (default: 1)')
    parser.add_argument('--outputs', type=int, default=2, help='number of outputs per transaction (default: 2)')
    parser.add_argument('--count', type=int, default=1,
                        help='number of independent txs to add/average over (default: 1)')
    parser.add_argument('--output-type', choices=OUTPUT_TYPES, default='htr',
                        help='type of the tx outputs (default: htr)')
    add_common_args(parser)
    args = parser.parse_args()

    dag_str, targets = build_tx_dag(
        num_inputs=args.inputs,
        num_outputs=args.outputs,
        count=args.count,
        output_type=args.output_type,
    )

    print(f'Building DAG: {args.count} tx(s) x {args.inputs} input(s) x {args.outputs} '
          f'output(s) [{args.output_type}]')

    manager = build_manager(seed=args.seed)
    artifacts = get_dag_builder(manager).build_from_str(dag_str)

    profile_on_new_tx(
        manager,
        artifacts,
        is_target=lambda name: name in targets,
        output=args.output,
        sort=args.sort,
        limit=args.limit,
        include_deserialization=not args.no_deserialization,
    )


if __name__ == '__main__':
    main()
