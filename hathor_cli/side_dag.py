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

import os
import signal
import sys
import time
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import Enum
from multiprocessing import Process
from typing import TYPE_CHECKING, Any

from setproctitle import setproctitle
from typing_extensions import assert_never, override

from hathor_cli.run_node_args import RunNodeArgs  # skip-cli-import-custom-check

if TYPE_CHECKING:
    from hathor_cli.util import LoggingOutput

from structlog import get_logger

from hathor_cli.run_node import RunNode

logger = get_logger()

PRE_SETUP_LOGGING: bool = False

# Period in seconds for polling subprocesses' state.
MONITOR_WAIT_PERIOD: int = 10

# Delay in seconds before killing a subprocess after trying to terminate it.
KILL_WAIT_DELAY = 300


class SideDagArgs(RunNodeArgs):
    poa_signer_file: str | None = None


class SideDagRunNode(RunNode):
    env_vars_prefix = 'hathor_side_dag_'

    @override
    def _parse_args_obj(self, args: dict[str, Any]) -> RunNodeArgs:
        return SideDagArgs.model_validate(args)

    @classmethod
    @override
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument('--poa-signer-file', help='File containing the Proof-of-Authority signer private key.')
        return parser


def main(capture_stdout: bool) -> None:
    """
    This command runs two full node instances in separate processes.

    The main process runs a side-dag full node, and it accepts the same options as the `run_node` command. Options
    with the `--side-dag` prefix are passed to the side-dag full node, while options without this prefix are passed
    to the non-side-dag full node, which runs in a background process and is commonly just a Hathor full node.
    Whenever one of the full nodes fail, the other is automatically terminated.

    The only exception is log configuration, which is set using a single option. By default, both full nodes output
    logs to stdout. Here's an example changing both logs to json:

    ```bash
    $ python -m hathor run_node_with_side_dag
        --testnet
        --procname-prefix testnet-
        --temp-data
        --side-dag-config-yaml ./my-side-dag.yml
        --side-dag-procname-prefix my-side-dag-
        --side-dag-temp-data
        --json-logs both
    ```

    In this example, Hathor testnet logs would be disabled, while side-dag logs would be outputted to stdout as json.
    """
    from hathor_cli.util import process_logging_options, setup_logging
    argv = sys.argv[1:]
    hathor_logging_output, side_dag_logging_output = _process_logging_output(argv)
    hathor_node_argv, side_dag_argv = _partition_argv(argv)

    # the main process uses the same configuration as the hathor process
    log_options = process_logging_options(hathor_node_argv.copy())
    setup_logging(
        logging_output=hathor_logging_output,
        logging_options=log_options,
        capture_stdout=capture_stdout,
        extra_log_info=_get_extra_log_info('monitor')
    )

    hathor_node_process = _start_node_process(
        argv=hathor_node_argv,
        runner=RunNode,
        logging_output=hathor_logging_output,
        capture_stdout=capture_stdout,
        name='hathor',
    )
    side_dag_node_process = _start_node_process(
        argv=side_dag_argv,
        runner=SideDagRunNode,
        logging_output=side_dag_logging_output,
        capture_stdout=capture_stdout,
        name='side-dag',
    )

    logger.info(
        'starting nodes',
        monitor_pid=os.getpid(),
        hathor_node_pid=hathor_node_process.pid,
        side_dag_node_pid=side_dag_node_process.pid
    )

    _run_monitor_process(hathor_node_process, side_dag_node_process)


def _process_logging_output(argv: list[str]) -> tuple[LoggingOutput, LoggingOutput]:
    """Extract logging output before argv parsing."""
    from hathor_cli.util import LoggingOutput, create_parser

    class LogOutputConfig(str, Enum):
        HATHOR = 'hathor'
        SIDE_DAG = 'side-dag'
        BOTH = 'both'

    parser = create_parser(add_help=False)
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


def _run_monitor_process(*processes: Process) -> None:
    """Function to be called by the main process to run the side-dag full node."""
    setproctitle('hathor-core: monitor')
    signal.signal(signal.SIGINT, lambda _, __: _terminate_and_exit(processes, reason='received SIGINT'))
    signal.signal(signal.SIGTERM, lambda _, __: _terminate_and_exit(processes, reason='received SIGTERM'))

    while True:
        time.sleep(MONITOR_WAIT_PERIOD)
        for process in processes:
            if not process.is_alive():
                _terminate_and_exit(
                    processes,
                    reason=f'process "{process.name}" (pid: {process.pid}) exited'
                )


def _terminate_and_exit(processes: tuple[Process, ...], *, reason: str) -> None:
    """Terminate all processes that are alive. Kills them if they're not terminated after a while.
    Then, exits the program."""
    logger.critical(f'terminating all nodes. reason: {reason}')

    for process in processes:
        if process.is_alive():
            logger.critical(f'terminating process "{process.name}" (pid: {process.pid})...')
            process.terminate()

    now = time.time()
    while True:
        time.sleep(MONITOR_WAIT_PERIOD)
        if time.time() >= now + KILL_WAIT_DELAY:
            _kill_all(processes)
            break

        all_are_dead = all(not process.is_alive() for process in processes)
        if all_are_dead:
            break

    logger.critical('all nodes terminated.')
    sys.exit(0)


def _kill_all(processes: tuple[Process, ...]) -> None:
    """Kill all processes that are alive."""
    for process in processes:
        if process.is_alive():
            logger.critical(f'process "{process.name}" (pid: {process.pid}) still alive, killing it...')
            process.kill()


def _start_node_process(
    *,
    argv: list[str],
    runner: type[RunNode],
    logging_output: LoggingOutput,
    capture_stdout: bool,
    name: str,
) -> Process:
    """Create and start a Hathor node process."""
    args = _RunNodeArgs(
        argv=argv,
        runner=runner,
        logging_output=logging_output,
        capture_stdout=capture_stdout,
        name=name
    )
    process = Process(target=_run_node, args=(args,), name=name)
    process.start()
    return process


@dataclass(frozen=True, slots=True, kw_only=True)
class _RunNodeArgs:
    argv: list[str]
    runner: type[RunNode]
    logging_output: LoggingOutput
    capture_stdout: bool
    name: str


def _run_node(args: _RunNodeArgs) -> None:
    from hathor_cli.util import process_logging_options, setup_logging
    try:
        log_options = process_logging_options(args.argv)
        setup_logging(
            logging_output=args.logging_output,
            logging_options=log_options,
            capture_stdout=args.capture_stdout,
            extra_log_info=_get_extra_log_info(args.name)
        )
        logger.info(f'initializing node "{args.name}"')
        node = args.runner(argv=args.argv)
    except KeyboardInterrupt:
        logger.warn(f'{args.name} node interrupted by user')
        return
    except (BaseException, Exception):
        logger.exception(f'process "{args.name}" terminated due to exception in initialization')
        return

    node.run()
    logger.critical(f'node "{args.name}" gracefully terminated')


def _get_extra_log_info(process_name: str) -> dict[str, str]:
    """Return a dict to be used as extra log info for each process."""
    return dict(_source_process=process_name)
