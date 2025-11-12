#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

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
