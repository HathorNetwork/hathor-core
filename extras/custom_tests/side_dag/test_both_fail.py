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

import os
import shlex
import signal
import subprocess
import sys

from utils import (  # type: ignore[import-not-found]
    COMMAND,
    HATHOR_PROCESS_NAME,
    KILL_WAIT_DELAY,
    MONITOR_PROCESS_NAME,
    SIDE_DAG_PROCESS_NAME,
    get_pid_by_name,
    is_alive,
    popen_is_alive,
    wait_seconds,
)

if sys.platform == 'win32':
    print("test skipped on windows")
    sys.exit(0)


def test_both_fail() -> None:
    # Assert that there are no existing processes
    assert get_pid_by_name(MONITOR_PROCESS_NAME) is None
    assert get_pid_by_name(HATHOR_PROCESS_NAME) is None
    assert get_pid_by_name(SIDE_DAG_PROCESS_NAME) is None

    # Run the python command
    args = shlex.split(COMMAND)
    monitor_process = subprocess.Popen(args)
    print(f'running "run_node_with_side_dag" in the background with pid: {monitor_process.pid}')
    print('awaiting subprocesses initialization...')
    wait_seconds(5)

    monitor_process_pid = get_pid_by_name(MONITOR_PROCESS_NAME)
    hathor_process_pid = get_pid_by_name(HATHOR_PROCESS_NAME)
    side_dag_process_pid = get_pid_by_name(SIDE_DAG_PROCESS_NAME)

    # Assert that the processes exist and are alive
    assert monitor_process_pid == monitor_process.pid
    assert monitor_process_pid is not None
    assert hathor_process_pid is not None
    assert side_dag_process_pid is not None

    assert is_alive(monitor_process_pid)
    assert is_alive(hathor_process_pid)
    assert is_alive(side_dag_process_pid)

    print('processes are running:')
    print(f'  "{MONITOR_PROCESS_NAME}" pid: {monitor_process_pid}')
    print(f'  "{HATHOR_PROCESS_NAME}" pid: {hathor_process_pid}')
    print(f'  "{SIDE_DAG_PROCESS_NAME}" pid: {side_dag_process_pid}')
    print('letting processes run for a while...')
    wait_seconds(10)

    # Terminate both subprocess
    print('terminating subprocesses...')
    os.kill(hathor_process_pid, signal.SIGTERM)
    os.kill(side_dag_process_pid, signal.SIGTERM)
    print('awaiting processes termination...')
    wait_seconds(KILL_WAIT_DELAY, break_function=lambda: not popen_is_alive(monitor_process))

    # Assert that all process are terminated
    assert not popen_is_alive(monitor_process)
    assert not is_alive(monitor_process_pid)
    assert not is_alive(hathor_process_pid)
    assert not is_alive(side_dag_process_pid)

    print('all processes are dead. test succeeded!')


try:
    test_both_fail()
except Exception:
    if monitor_process_pid := get_pid_by_name(MONITOR_PROCESS_NAME):
        os.kill(monitor_process_pid, signal.SIGKILL)
    if hathor_process_pid := get_pid_by_name(HATHOR_PROCESS_NAME):
        os.kill(hathor_process_pid, signal.SIGKILL)
    if side_dag_process_pid := get_pid_by_name(SIDE_DAG_PROCESS_NAME):
        os.kill(side_dag_process_pid, signal.SIGKILL)

    raise
