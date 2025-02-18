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
import subprocess
import time
from typing import Callable

MONITOR_PROCESS_NAME = 'hathor-core: monitor'
PROCNAME_SUFFIX = 'hathor-core'
HATHOR_PROCESS_PREFIX = 'hathor:'
SIDE_DAG_PROCESS_PREFIX = 'side-dag:'
HATHOR_PROCESS_NAME = HATHOR_PROCESS_PREFIX + PROCNAME_SUFFIX
SIDE_DAG_PROCESS_NAME = SIDE_DAG_PROCESS_PREFIX + PROCNAME_SUFFIX
KILL_WAIT_DELAY = 305

COMMAND = f"""
    python -m hathor run_node_with_side_dag
        --disable-logs
        --testnet
        --temp-data
        --x-localhost-only
        --procname-prefix {HATHOR_PROCESS_PREFIX}
        --side-dag-testnet
        --side-dag-temp-data
        --side-dag-x-localhost-only
        --side-dag-procname-prefix {SIDE_DAG_PROCESS_PREFIX}
"""


def wait_seconds(seconds: int, *, break_function: Callable[[], bool] | None = None) -> None:
    while seconds > 0:
        print(f'waiting {seconds} seconds...')
        time.sleep(1)
        seconds -= 1
        if break_function and break_function():
            break


def get_pid_by_name(process_name: str) -> int | None:
    try:
        output = subprocess.check_output(['pgrep', '-f', process_name], text=True)
    except subprocess.CalledProcessError:
        return None
    pids = output.strip().split()
    assert len(pids) <= 1
    try:
        return int(pids[0])
    except IndexError:
        return None


def is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def popen_is_alive(popen: subprocess.Popen) -> bool:
    try:
        popen.wait(0)
    except subprocess.TimeoutExpired:
        return True
    assert popen.returncode is not None
    return False
