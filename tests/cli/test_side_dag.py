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

from unittest.mock import ANY, Mock, call, patch

import pytest

from hathor.cli import side_dag
from hathor.cli.side_dag import (
    HathorProcessInitFail,
    HathorProcessInitSuccess,
    HathorProcessTerminated,
    SideDagProcessTerminated,
    _partition_argv,
    _run_hathor_node,
    _run_side_dag_node,
    main,
)
from hathor.cli.util import LoggingOutput


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
def test_process_argv(
    argv: list[str],
    expected_hathor_node_argv: list[str],
    expected_side_dag_argv: list[str]
) -> None:
    hathor_node_argv, side_dag_argv = _partition_argv(argv)

    assert hathor_node_argv == expected_hathor_node_argv
    assert side_dag_argv == expected_side_dag_argv


def test_run_side_dag_node_hathor_init_timed_out() -> None:
    argv: list[str] = []
    conn_mock = Mock()
    conn_mock.poll = Mock(return_value=False)
    hathor_node_process = Mock()

    with patch.object(side_dag, 'SideDagRunNode') as side_dag_mock:
        _run_side_dag_node(argv, conn=conn_mock, hathor_node_process=hathor_node_process)
        side_dag_mock.assert_not_called()
        hathor_node_process.terminate.assert_not_called()
        conn_mock.send.assert_not_called()


def test_run_side_dag_node_hathor_init_failed() -> None:
    argv: list[str] = []
    conn_mock = Mock()
    conn_mock.poll = Mock(return_value=True)
    conn_mock.recv = Mock(return_value=HathorProcessInitFail('some reason'))
    hathor_node_process = Mock()

    with patch.object(side_dag, 'SideDagRunNode') as side_dag_mock:
        _run_side_dag_node(argv, conn=conn_mock, hathor_node_process=hathor_node_process)
        side_dag_mock.assert_not_called()
        hathor_node_process.terminate.assert_not_called()
        conn_mock.send.assert_not_called()


def test_run_side_dag_node_init_failed() -> None:
    argv: list[str] = []
    conn_mock = Mock()
    conn_mock.poll = Mock(return_value=True)
    conn_mock.recv = Mock(return_value=HathorProcessInitSuccess())
    hathor_node_process = Mock()
    side_dag_mock = Mock(side_effect=Exception)

    with patch.object(side_dag, 'SideDagRunNode', side_dag_mock):
        _run_side_dag_node(argv, conn=conn_mock, hathor_node_process=hathor_node_process)
        side_dag_mock.assert_called_once_with(argv=argv)
        hathor_node_process.terminate.assert_called_once()
        conn_mock.send.assert_called_once_with(SideDagProcessTerminated())


def test_run_side_dag_node_hathor_terminated() -> None:
    argv: list[str] = []
    conn_mock = Mock()
    conn_mock.poll = Mock(side_effect=[True, True])
    conn_mock.recv = Mock(side_effect=[HathorProcessInitSuccess(), HathorProcessTerminated()])
    hathor_node_process = Mock()
    side_dag_instance_mock = Mock()
    side_dag_mock = Mock(return_value=side_dag_instance_mock)

    with patch.object(side_dag, 'SideDagRunNode', side_dag_mock):
        _run_side_dag_node(argv, conn=conn_mock, hathor_node_process=hathor_node_process)
        side_dag_mock.assert_called_once_with(argv=argv)
        side_dag_instance_mock.run.assert_called_once()
        hathor_node_process.terminate.assert_not_called()
        conn_mock.send.assert_not_called()


def test_run_side_dag_node_terminated() -> None:
    argv: list[str] = []
    conn_mock = Mock()
    conn_mock.poll = Mock(side_effect=[True, False])
    conn_mock.recv = Mock(side_effect=[HathorProcessInitSuccess()])
    hathor_node_process = Mock()
    side_dag_instance_mock = Mock()
    side_dag_mock = Mock(return_value=side_dag_instance_mock)

    with patch.object(side_dag, 'SideDagRunNode', side_dag_mock):
        _run_side_dag_node(argv, conn=conn_mock, hathor_node_process=hathor_node_process)
        side_dag_mock.assert_called_once_with(argv=argv)
        side_dag_instance_mock.run.assert_called_once()
        hathor_node_process.terminate.assert_called_once()
        conn_mock.send.assert_called_once_with(SideDagProcessTerminated())


def test_run_hathor_node_init_failed() -> None:
    argv: list[str] = []
    run_node_cmd_mock = Mock(side_effect=Exception)
    capture_stdout = False
    conn_mock = Mock()
    parent_process_mock = Mock()

    with patch('psutil.Process', return_value=parent_process_mock):
        _run_hathor_node(argv, run_node_cmd_mock, LoggingOutput.PRETTY, capture_stdout, conn_mock)
        run_node_cmd_mock.assert_called_once_with(argv=argv)
        conn_mock.send.assert_called_once_with(HathorProcessInitFail(ANY))
        parent_process_mock.terminate.assert_not_called()


def test_run_hathor_node_side_dag_terminated() -> None:
    argv: list[str] = []
    run_node_instance = Mock()
    run_node_cmd_mock = Mock(return_value=run_node_instance)
    capture_stdout = False
    conn_mock = Mock()
    conn_mock.poll = Mock(return_value=True)
    conn_mock.recv = Mock(return_value=SideDagProcessTerminated())
    parent_process_mock = Mock()

    with patch('psutil.Process', return_value=parent_process_mock):
        _run_hathor_node(argv, run_node_cmd_mock, LoggingOutput.PRETTY, capture_stdout, conn_mock)
        conn_mock.send.assert_called_once_with(HathorProcessInitSuccess())
        run_node_instance.run.assert_called_once()
        parent_process_mock.terminate.assert_not_called()


def test_run_hathor_node_exited() -> None:
    argv: list[str] = []
    run_node_instance = Mock()
    run_node_cmd_mock = Mock(return_value=run_node_instance)
    capture_stdout = False
    conn_mock = Mock()
    conn_mock.poll = Mock(return_value=False)
    parent_process_mock = Mock()

    with patch('psutil.Process', return_value=parent_process_mock):
        _run_hathor_node(argv, run_node_cmd_mock, LoggingOutput.PRETTY, capture_stdout, conn_mock)
        conn_mock.send.assert_has_calls([call(HathorProcessInitSuccess()), call(HathorProcessTerminated())])
        run_node_instance.run.assert_called_once()
        parent_process_mock.terminate.assert_called_once()


def dummy_run_hathor_node() -> None:
    pass


def test_main_success() -> None:
    with (
        patch.object(side_dag, '_run_side_dag_node') as run_side_dag_mock,
        patch.object(side_dag, '_run_hathor_node', dummy_run_hathor_node),

    ):
        main(capture_stdout=False)
        run_side_dag_mock.assert_called_once()
