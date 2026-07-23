# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import pytest

from hathor_cli.side_dag import _partition_argv


@pytest.mark.parametrize(
    ['argv', 'expected_hathor_node_argv', 'expected_side_dag_argv'],
    [
        (
            ['--testnet', '--side-dag-testnet'],
            ['--testnet'],
            ['--testnet'],
        ),
        (
            ['--testnet', '--some-config', 'config', '--side-dag-some-other-config', 'other-config'],
            ['--testnet', '--some-config', 'config'],
            ['--some-other-config', 'other-config'],
        ),
        (
            ['--side-dag-A', 'A', '--side-dag-B', '--B', 'B', '--side-dag-C', 'C'],
            ['--B', 'B'],
            ['--A', 'A', '--B', '--C', 'C'],
        ),
    ]
)
def test_partition_argv(
    argv: list[str],
    expected_hathor_node_argv: list[str],
    expected_side_dag_argv: list[str]
) -> None:
    hathor_node_argv, side_dag_argv = _partition_argv(argv)

    assert hathor_node_argv == expected_hathor_node_argv
    assert side_dag_argv == expected_side_dag_argv
