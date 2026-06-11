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

"""Parallel execution of per-input script (signature) verification.

The slowest part of verifying a transaction is checking the ECDSA signatures of its inputs. Each input's script
evaluation is a pure function of a few bytes (the input data, the spent output's script, the transaction's sighash
data, its timestamp and, for the V1-only OP_FIND_P2PKH, the transaction outputs). This module packages that data
into a self-contained, picklable :class:`ScriptVerificationJob` and runs the jobs on a worker pool, so the
signature checks of a single transaction can be verified in parallel.

The pool is built around :class:`concurrent.futures.Executor` so the thread-vs-process choice is a configuration
detail. The top-level verification call stays synchronous: ``run_jobs`` submits one future per job and blocks until
all complete, returning the results in input order.
"""

from __future__ import annotations

import multiprocessing
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Sequence

from hathor.transaction.exceptions import ScriptError
from hathor.transaction.scripts.execute import DetachedUtxoScriptExtras, raw_script_eval

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, Transaction, TxInput
    from hathor.transaction.scripts.opcode import OpcodesVersion


class ScriptVerificationMode(str, Enum):
    """How input script verification is executed."""
    DISABLED = 'disabled'   # serial, inline on the calling thread (default)
    THREADS = 'threads'     # concurrent.futures.ThreadPoolExecutor
    PROCESSES = 'processes'  # concurrent.futures.ProcessPoolExecutor (spawn)


@dataclass(slots=True, frozen=True, kw_only=True)
class ScriptVerificationJob:
    """A self-contained, picklable description of one input's script evaluation.

    It carries only primitive data so it can be shipped to a worker thread or process without pickling whole
    transaction objects or touching storage.
    """
    input_index: int
    input_data: bytes
    output_script: bytes
    sighash_all_data: bytes
    tx_timestamp: int
    spent_output_value: int
    # (value, script) for each tx output; only the V1 OP_FIND_P2PKH reads this, so it is empty for V2+.
    tx_outputs: tuple[tuple[int, bytes], ...]
    opcodes_version: OpcodesVersion


def build_script_verification_job(
    *,
    input_index: int,
    tx: Transaction,
    txin: TxInput,
    spent_tx: BaseTransaction,
    opcodes_version: OpcodesVersion,
    shared_outputs: tuple[tuple[int, bytes], ...],
) -> ScriptVerificationJob:
    """Build a :class:`ScriptVerificationJob` for one input. Must run on the main thread (touches storage via the
    already-fetched ``spent_tx`` and computes the cached sighash).

    ``shared_outputs`` is the per-transaction outputs tuple, built once and shared by all of the tx's jobs (empty
    when ``opcodes_version`` does not enable OP_FIND_P2PKH).
    """
    spent_output = spent_tx.resolve_spent_output(txin.index)
    return ScriptVerificationJob(
        input_index=input_index,
        input_data=txin.data,
        output_script=spent_output.script,
        sighash_all_data=tx.get_sighash_all_data(),
        tx_timestamp=tx.timestamp,
        spent_output_value=spent_output.value,
        tx_outputs=shared_outputs,
        opcodes_version=opcodes_version,
    )


def execute_script_verification_job(job: ScriptVerificationJob) -> ScriptError | None:
    """Evaluate one input's script. Top-level (picklable) so it can run in a worker process.

    Returns the raised :class:`ScriptError` instead of raising it, so the caller can gather results in input order
    and reproduce the serial path's deterministic error semantics (and to avoid relying on cross-process pickling
    of chained exceptions).
    """
    extras = DetachedUtxoScriptExtras(
        version=job.opcodes_version,
        sighash_all_data=job.sighash_all_data,
        timestamp=job.tx_timestamp,
        spent_output_value=job.spent_output_value,
        tx_outputs=job.tx_outputs,
    )
    try:
        raw_script_eval(input_data=job.input_data, output_script=job.output_script, extras=extras)
    except ScriptError as e:
        return e
    return None


def _warmup_worker(_: int) -> None:
    """No-op submitted at startup to force thread/process creation (so the cost is paid at boot, not on the
    first transaction). Must be a top-level function to be picklable for the process pool."""
    return None


class ScriptVerificationPool:
    """Owns the executor used to verify input scripts in parallel.

    Lifecycle mirrors the existing PoW thread pool: created disabled/idle, ``start()``-ed by the manager and
    ``stop()``-ed on shutdown. When disabled, or when a transaction has fewer than ``min_inputs`` inputs, jobs run
    serially inline so single-input transactions never pay pool overhead.
    """

    __slots__ = ('_mode', '_num_workers', '_min_inputs', '_executor')

    def __init__(self, *, mode: ScriptVerificationMode, num_workers: int, min_inputs: int = 2) -> None:
        self._mode = mode
        self._num_workers = num_workers
        self._min_inputs = max(1, min_inputs)
        self._executor: Executor | None = None

    @property
    def enabled(self) -> bool:
        """Whether a worker pool will actually be used (mode set and at least one worker)."""
        return self._mode is not ScriptVerificationMode.DISABLED and self._num_workers > 0

    @property
    def started(self) -> bool:
        return self._executor is not None

    def start(self) -> None:
        """Create and warm up the executor. No-op when disabled or already started."""
        if not self.enabled or self._executor is not None:
            return
        if self._mode is ScriptVerificationMode.THREADS:
            self._executor = ThreadPoolExecutor(max_workers=self._num_workers, thread_name_prefix='script-verify')
        elif self._mode is ScriptVerificationMode.PROCESSES:
            # spawn: never fork a process holding RocksDB handles / Twisted threads.
            mp_context = multiprocessing.get_context('spawn')
            self._executor = ProcessPoolExecutor(max_workers=self._num_workers, mp_context=mp_context)
        else:
            raise ValueError(f'unsupported script verification mode: {self._mode}')
        # Warm up: force worker creation now (important for the process pool's spawn cost).
        warmup = [self._executor.submit(_warmup_worker, i) for i in range(self._num_workers)]
        for future in warmup:
            future.result()

    def stop(self) -> None:
        """Shut down the executor. Safe to call when not started."""
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    def run_jobs(self, jobs: Sequence[ScriptVerificationJob]) -> list[ScriptError | None]:
        """Run all jobs and return their results in input order (``None`` == valid, else the ScriptError).

        Falls back to a serial inline loop when the pool is not started or when there are too few jobs to be worth
        the fan-out overhead (``len(jobs) < min_inputs``).
        """
        if self._executor is None or len(jobs) < self._min_inputs:
            return [execute_script_verification_job(job) for job in jobs]
        futures = [self._executor.submit(execute_script_verification_job, job) for job in jobs]
        return [future.result() for future in futures]
