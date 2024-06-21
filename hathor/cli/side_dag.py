# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import argparse
import os
import signal
import sys
import traceback
from dataclasses import dataclass
from enum import Enum
from multiprocessing import Pipe, Process
from typing import TYPE_CHECKING

from typing_extensions import assert_never

if TYPE_CHECKING:
    from hathor.cli.util import LoggingOutput

    # Workaround for a typing issue in Windows
    if sys.platform == 'win32':
        from multiprocessing.connection import _ConnectionBase as Connection
    else:
        from multiprocessing.connection import Connection

import psutil
from structlog import get_logger

from hathor.cli.run_node import RunNode

logger = get_logger()

PRE_SETUP_LOGGING: bool = False
HATHOR_NODE_INIT_TIMEOUT: int = 10


@dataclass(frozen=True, slots=True)
class HathorProcessInitFail:
    reason: str


@dataclass(frozen=True, slots=True)
class HathorProcessInitSuccess:
    pass


@dataclass(frozen=True, slots=True)
class HathorProcessTerminated:
    pass


@dataclass(frozen=True, slots=True)
class SideDagProcessTerminated:
    pass


class SideDagRunNode(RunNode):
    env_vars_prefix = 'hathor_side_dag_'


def main(capture_stdout: bool) -> None:
    """
    This command runs two full node instances in separate processes.

    The main process runs a side-dag full node, and it accepts the same options as the `run_node` command. Options
    with the `--side-dag` prefix are passed to the side-dag full node, while options without this prefix are passed
    to the non-side-dag full node, which runs in a background process and is commonly just a Hathor full node.
    Whenever one of the full nodes fail, the other is automatically terminated.

    By default, both full nodes output logs to stdout, but logs can be configured independently. Here's an example:

    ```bash
    $ python -m hathor side_dag
        --testnet
        --procname-prefix testnet-
        --memory-storage
        --disable-logs
        --side-dag-config-yaml ./my-side-dag.yml
        --side-dag-procname-prefix my-side-dag-
        --side-dag-memory-storage
        --side-dag-json-logs
    ```

    In this example, Hathor testnet logs would be disabled, while side-dag logs would be outputted to stdout as json.
    """
    from hathor.cli.util import process_logging_options, setup_logging
    argv = sys.argv[1:]
    hathor_logging_output, side_dag_logging_output = _process_logging_output(argv)
    hathor_node_argv, side_dag_argv = _partition_argv(argv)
    conn1, conn2 = Pipe()
    hathor_node_process = _start_hathor_node_process(
        hathor_node_argv, logging_output=hathor_logging_output, capture_stdout=capture_stdout, conn=conn1
    )

    log_options = process_logging_options(side_dag_argv)
    setup_logging(logging_output=side_dag_logging_output, logging_options=log_options, capture_stdout=capture_stdout)
    logger.info('starting nodes', hathor_node_pid=hathor_node_process.pid, side_dag_pid=os.getpid())

    _run_side_dag_node(side_dag_argv, hathor_node_process=hathor_node_process, conn=conn2)


def _process_logging_output(argv: list[str]) -> tuple[LoggingOutput, LoggingOutput]:
    """Extract logging output before argv parsing."""
    from hathor.cli.util import LoggingOutput

    class LogOutputConfig(str, Enum):
        HATHOR = 'hathor'
        SIDE_DAG = 'side-dag'
        BOTH = 'both'

    parser = argparse.ArgumentParser(add_help=False)
    log_args = parser.add_mutually_exclusive_group()
    log_args.add_argument('--json-logs', nargs='?', const='both', type=LogOutputConfig)
    log_args.add_argument('--disable-logs', nargs='?', const='both', type=LogOutputConfig)

    args, remaining_argv = parser.parse_known_args(argv)
    argv.clear()
    argv.extend(remaining_argv)

    def proces_log_output_config(
        config: LogOutputConfig,
        target: LoggingOutput
    ) -> tuple[LoggingOutput, LoggingOutput]:
        hathor_output, side_dag_output = LoggingOutput.PRETTY, LoggingOutput.PRETTY
        match config:
            case LogOutputConfig.HATHOR:
                hathor_output = target
            case LogOutputConfig.SIDE_DAG:
                side_dag_output = target
            case LogOutputConfig.BOTH:
                hathor_output, side_dag_output = target, target
            case _:
                assert_never(config)
        return hathor_output, side_dag_output

    if args.json_logs:
        return proces_log_output_config(args.json_logs, LoggingOutput.JSON)

    if args.disable_logs:
        return proces_log_output_config(args.disable_logs, LoggingOutput.NULL)

    return LoggingOutput.PRETTY, LoggingOutput.PRETTY


def _partition_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Partition arguments into hathor node args and side-dag args, based on the `--side-dag` prefix."""
    hathor_node_argv: list[str] = []
    side_dag_argv: list[str] = []

    def is_option(arg_: str) -> bool:
        return arg_.startswith('--')

    for i, arg in enumerate(argv):
        if not is_option(arg):
            continue

        try:
            value = None if is_option(argv[i + 1]) else argv[i + 1]
        except IndexError:
            value = None

        argv_list = hathor_node_argv
        if arg.startswith('--side-dag'):
            arg = arg.replace('--side-dag-', '--')
            argv_list = side_dag_argv

        argv_list.append(arg)
        if value is not None:
            argv_list.append(value)

    return hathor_node_argv, side_dag_argv


def _run_side_dag_node(argv: list[str], *, hathor_node_process: Process, conn: 'Connection') -> None:
    """Function to be called by the main process to run the side-dag full node."""
    logger.info('waiting for hathor node to initialize...')
    if not conn.poll(HATHOR_NODE_INIT_TIMEOUT):
        logger.critical(
            f'side-dag node not started because hathor node failed to initialize before {HATHOR_NODE_INIT_TIMEOUT} '
            f'seconds timeout'
        )
        return

    message = conn.recv()
    if isinstance(message, HathorProcessInitFail):
        logger.critical(f'side-dag node not started because hathor node initialization failed:\n{message.reason}')
        return

    assert isinstance(message, HathorProcessInitSuccess)
    logger.info('hathor node initialized')
    logger.info('starting side-dag node...')

    try:
        side_dag = SideDagRunNode(argv=argv)
    except (BaseException, Exception):
        logger.critical('terminating hathor node...')
        conn.send(SideDagProcessTerminated())
        hathor_node_process.terminate()
        return

    side_dag.run()

    # If `run()` returns, either the hathor node exited and terminated us, leaving the message below, or the side-dag
    # node exited and we will terminate the hathor node.
    if conn.poll():
        message = conn.recv()
        assert isinstance(message, HathorProcessTerminated)
        logger.critical('side-dag node terminated because hathor node exited')
        return

    conn.send(SideDagProcessTerminated())
    logger.critical('terminating hathor node...')
    hathor_node_process.terminate()


def _start_hathor_node_process(
    argv: list[str],
    *,
    logging_output: LoggingOutput,
    capture_stdout: bool,
    conn: 'Connection',
) -> Process:
    """Create and start a Hathor node process."""
    run_hathor_node_args = (argv, RunNode, logging_output, capture_stdout, conn)
    hathor_node_process = Process(target=_run_hathor_node, args=run_hathor_node_args)
    hathor_node_process.start()
    return hathor_node_process


def _run_hathor_node(
    argv: list[str],
    run_node_cmd: type[RunNode],
    logging_output: LoggingOutput,
    capture_stdout: bool,
    conn: 'Connection',
) -> None:
    """Function to be called by a background process to run the Hathor full node."""
    from hathor.cli.util import process_logging_options, setup_logging

    # We don't terminate via SIGINT directly, instead the side-dag process will terminate us.
    signal.signal(signal.SIGINT, lambda _, __: None)
    try:
        log_options = process_logging_options(argv)
        setup_logging(logging_output=logging_output, logging_options=log_options, capture_stdout=capture_stdout)
        hathor_node = run_node_cmd(argv=argv)
    except (BaseException, Exception):
        conn.send(HathorProcessInitFail(traceback.format_exc()))
        return

    conn.send(HathorProcessInitSuccess())
    hathor_node.run()

    # If `run()` returns, either the side-dag node exited and terminated us, leaving the message below, or the hathor
    # node exited and we will terminate the side-dag node.
    if conn.poll():
        message = conn.recv()
        assert isinstance(message, SideDagProcessTerminated)
        logger.critical('hathor node terminated because side-dag process was terminated')
        return

    conn.send(HathorProcessTerminated())
    logger.critical('terminating side-dag node...')
    parent_pid = os.getppid()
    parent_process = psutil.Process(parent_pid)
    parent_process.terminate()
