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
import struct
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable, NoReturn, Sequence, TypeVar

from structlog import get_logger

from hathor.transaction.exceptions import (
    DataIndexError,
    EqualVerifyFailed,
    FinalStackInvalid,
    InvalidOutputScriptSize,
    InvalidOutputValue,
    InvalidScriptError,
    InvalidStackData,
    InvalidToken,
    MissingStackItems,
    OracleChecksigFailed,
    OutOfData,
    PowError,
    ScriptError,
    TimeLocked,
    TooManyOutputs,
    VerifyFailed,
)
from hathor.transaction.scripts.execute import DetachedUtxoScriptExtras, raw_script_eval

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, Transaction, TxInput
    from hathor.transaction.scripts.opcode import OpcodesVersion

logger = get_logger()

_T = TypeVar('_T')


class ScriptVerificationMode(str, Enum):
    """How input script verification is executed."""
    DISABLED = 'disabled'   # serial, inline on the calling thread (default)
    THREADS = 'threads'     # concurrent.futures.ThreadPoolExecutor
    PROCESSES = 'processes'  # concurrent.futures.ProcessPoolExecutor (spawn)
    RUST = 'rust'           # htr_lib batch call (in-process rayon threads, GIL released)
    SHADOW_RUST = 'shadow-rust'  # Python is authoritative; Rust runs too and mismatches are logged


# Rust error kinds (htr_lib.verify_scripts_batch) that map to ScriptError subclasses. These become job *results*
# and are wrapped as InvalidInputData by the verifier's merge, exactly like the Python path.
_RUST_SCRIPT_ERRORS: dict[str, type[ScriptError]] = {
    'OutOfData': OutOfData,
    'MissingStackItems': MissingStackItems,
    'EqualVerifyFailed': EqualVerifyFailed,
    'FinalStackInvalid': FinalStackInvalid,
    'OracleChecksigFailed': OracleChecksigFailed,
    'DataIndexError': DataIndexError,
    'InvalidStackData': InvalidStackData,
    'VerifyFailed': VerifyFailed,
    'TimeLocked': TimeLocked,
    'ScriptError': ScriptError,
}


def _make_rust_raised_exception(kind: str, message: str) -> BaseException:
    """Build the exception for a Rust error kind that is *raised* out of ``run_jobs`` unwrapped, replicating the
    exact exception types the Python evaluator lets escape (``execute_script_verification_job`` catches only
    ``ScriptError``)."""
    match kind:
        case 'InvalidScriptError':
            return InvalidScriptError(message)
        case 'AssertionError':
            return AssertionError(message)
        case 'StructError':
            return struct.error(message)
        case 'IndexError':
            return IndexError(message)
        case 'UnicodeDecodeError':
            return UnicodeDecodeError('utf-8', b'', 0, 1, message or 'invalid utf-8')
        case _:
            raise ValueError(f'unknown rust script verification error kind: {kind}')


def _python_outcome_category(outcome: ScriptError | BaseException | None) -> str:
    """Categorize a Python evaluation outcome for shadow-mode comparison: the exception class name, normalized so
    it matches the Rust kind strings (``struct.error``'s class name is ``error``)."""
    if outcome is None:
        return 'valid'
    if isinstance(outcome, struct.error):
        return 'StructError'
    return type(outcome).__name__


# Rust error kinds from the stateless verification checks (htr_lib.verify_*): TxValidationError subclasses the
# corresponding Python verifier raises directly.
_RUST_VERIFICATION_ERRORS: dict[str, type[BaseException]] = {
    'TooManyOutputs': TooManyOutputs,
    'InvalidToken': InvalidToken,
    'InvalidOutputValue': InvalidOutputValue,
    'InvalidOutputScriptSize': InvalidOutputScriptSize,
    'PowError': PowError,
}


def raise_rust_error(kind: str, message: str) -> NoReturn:
    """Raise the Python exception a Rust ``(kind, message)`` error maps to. Used by verification checks where the
    Python reference lets the exception propagate raw (e.g. the sigops counting walk and the stateless checks)."""
    error_cls = _RUST_SCRIPT_ERRORS.get(kind) or _RUST_VERIFICATION_ERRORS.get(kind)
    if error_cls is not None:
        raise error_cls(message)
    raise _make_rust_raised_exception(kind, message)


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

    __slots__ = (
        '_mode',
        '_num_workers',
        '_min_inputs',
        '_executor',
        '_rust_started',
        '_max_multisig_pubkeys',
        '_max_multisig_signatures',
        '_p2pkh_version_byte',
        '_shadow_mismatches',
    )

    def __init__(self, *, mode: ScriptVerificationMode, num_workers: int, min_inputs: int = 2) -> None:
        self._mode = mode
        self._num_workers = num_workers
        self._min_inputs = max(1, min_inputs)
        self._executor: Executor | None = None
        self._rust_started = False
        self._max_multisig_pubkeys = 0
        self._max_multisig_signatures = 0
        self._p2pkh_version_byte = b''
        self._shadow_mismatches = 0

    @property
    def enabled(self) -> bool:
        """Whether a worker pool will actually be used (mode set and at least one worker)."""
        return self._mode is not ScriptVerificationMode.DISABLED and self._num_workers > 0

    @property
    def started(self) -> bool:
        return self._executor is not None or self._rust_started

    @property
    def shadow_mismatches(self) -> int:
        """Number of per-job Python/Rust disagreements observed in SHADOW_RUST mode."""
        return self._shadow_mismatches

    @property
    def _is_rust_mode(self) -> bool:
        return self._mode in (ScriptVerificationMode.RUST, ScriptVerificationMode.SHADOW_RUST)

    @property
    def rust_verification(self) -> bool:
        """Whether started in RUST mode: rust-backed verification checks replace the Python ones."""
        return self._rust_started and self._mode is ScriptVerificationMode.RUST

    @property
    def shadow_rust_verification(self) -> bool:
        """Whether started in SHADOW_RUST mode: Python stays authoritative, rust runs too and mismatches are
        logged and counted."""
        return self._rust_started and self._mode is ScriptVerificationMode.SHADOW_RUST

    def count_sigops_outputs(self, scripts: Sequence[bytes], *, enable_checkdatasig_count: bool) -> int:
        """Rust-backed output-sigops counting (`SigopCounter` over each output script). Raises exactly what the
        Python walk would raise on a malformed script (`OutOfData` / `InvalidScriptError`)."""
        import htr_lib
        error, total = htr_lib.count_sigops_outputs(
            list(scripts), self._max_multisig_pubkeys, enable_checkdatasig_count,
        )
        if error is not None:
            raise_rust_error(error[0], error[1])
        return total

    def rust_verify_outputs(
        self,
        outputs: Sequence[tuple[int, int, int]],
        *,
        max_num_outputs: int,
        max_output_script_size: int,
    ) -> None:
        """Rust-backed `VertexVerifier.verify_outputs` (incl. the number-of-outputs check) over marshalled
        ``(value, script_len, token_data)`` tuples."""
        import htr_lib
        error = htr_lib.verify_outputs(list(outputs), max_num_outputs, max_output_script_size)
        if error is not None:
            raise_rust_error(error[0], error[1])

    def rust_verify_output_token_indexes(self, token_data_list: Sequence[int], *, tokens_count: int) -> None:
        """Rust-backed `TransactionVerifier.verify_output_token_indexes`."""
        import htr_lib
        error = htr_lib.verify_output_token_indexes(list(token_data_list), tokens_count)
        if error is not None:
            raise_rust_error(error[0], error[1])

    def rust_verify_pow(self, vertex_hash: bytes, target: int) -> None:
        """Rust-backed `VertexVerifier.verify_pow` comparison. The target is the Python-computed
        ``vertex.get_target()`` value (the float math stays in Python so there is no libm-divergence risk);
        negative targets (possible for absurdly large weights, where ``2**x`` underflows) clamp to zero, which
        rejects every hash exactly like the negative target does."""
        import htr_lib
        target = max(target, 0)
        target_bytes = target.to_bytes(max(1, (target.bit_length() + 7) // 8), 'big')
        error = htr_lib.verify_pow(vertex_hash, target_bytes)
        if error is not None:
            raise_rust_error(error[0], error[1])

    def run_shadow_check(self, check: str, python_fn: Callable[[], _T], rust_fn: Callable[[], _T]) -> _T:
        """Run a verification check through Python (authoritative) and Rust, compare the outcome categories
        (returned value or exception class), and log + count any disagreement. Always returns/raises the Python
        outcome."""
        python_error: BaseException | None = None
        python_result: _T | None = None
        try:
            python_result = python_fn()
        except BaseException as e:
            python_error = e

        try:
            rust_error: BaseException | None = None
            rust_result: _T | None = None
            try:
                rust_result = rust_fn()
            except BaseException as e:
                rust_error = e
            python_category = _python_outcome_category(python_error)
            rust_category = _python_outcome_category(rust_error)
            mismatch = python_category != rust_category or (
                python_error is None and python_result != rust_result
            )
            if mismatch:
                self._shadow_mismatches += 1
                logger.error(
                    'rust shadow verification mismatch',
                    check=check,
                    python_category=python_category,
                    rust_category=rust_category,
                    python_result=python_result,
                    rust_result=rust_result,
                )
        except Exception:
            self._shadow_mismatches += 1
            logger.error('rust shadow verification crashed', check=check, exc_info=True)

        if python_error is not None:
            raise python_error
        return python_result  # type: ignore[return-value]

    def start(self) -> None:
        """Create and warm up the executor (or the Rust thread pool). No-op when disabled or already started."""
        if not self.enabled or self.started:
            return
        if self._is_rust_mode:
            # The Rust path reads no global state: the settings the opcodes need are snapshotted here and passed
            # on every batch call.
            from hathor.conf.get_settings import get_global_settings
            settings = get_global_settings()
            self._max_multisig_pubkeys = settings.MAX_MULTISIG_PUBKEYS
            self._max_multisig_signatures = settings.MAX_MULTISIG_SIGNATURES
            self._p2pkh_version_byte = settings.P2PKH_VERSION_BYTE
            self._rust_started = True
            # Warm up: size and spawn the rayon thread pool now (its size is fixed on first call).
            self._verify_scripts_batch_rust([])
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
        self._rust_started = False

    def run_jobs(self, jobs: Sequence[ScriptVerificationJob]) -> list[ScriptError | None]:
        """Run all jobs and return their results in input order (``None`` == valid, else the ScriptError).

        Falls back to a serial inline loop when the pool is not started or when there are too few jobs to be worth
        the fan-out overhead (``len(jobs) < min_inputs``). The Rust modes skip the ``min_inputs`` gate: the batch
        call is a single in-process call, so it wins even at one input.
        """
        if self._rust_started:
            if self._mode is ScriptVerificationMode.SHADOW_RUST:
                return self._run_jobs_shadow(jobs)
            return self._run_jobs_rust(jobs)
        if self._executor is None or len(jobs) < self._min_inputs:
            return [execute_script_verification_job(job) for job in jobs]
        futures = [self._executor.submit(execute_script_verification_job, job) for job in jobs]
        return [future.result() for future in futures]

    def _verify_scripts_batch_rust(self, jobs: Sequence[ScriptVerificationJob]) -> list[tuple[str, str] | None]:
        """Call the Rust batch verifier with the snapshotted settings."""
        import htr_lib
        return htr_lib.verify_scripts_batch(
            list(jobs),
            self._max_multisig_pubkeys,
            self._max_multisig_signatures,
            self._p2pkh_version_byte,
            self._num_workers,
        )

    def _run_jobs_rust(self, jobs: Sequence[ScriptVerificationJob]) -> list[ScriptError | None]:
        """RUST mode: one batch call; map (kind, message) pairs back to the Python exception model."""
        if not jobs:
            return []
        raw = self._verify_scripts_batch_rust(jobs)
        results: list[ScriptError | None] = []
        for item in raw:
            if item is None:
                results.append(None)
                continue
            kind, message = item
            error_cls = _RUST_SCRIPT_ERRORS.get(kind)
            if error_cls is None:
                # Non-ScriptError kinds escape run_jobs unwrapped; raising at the first one in job order mirrors
                # both the serial loop and the executor paths' `future.result()` semantics.
                raise _make_rust_raised_exception(kind, message)
            results.append(error_cls(message))
        return results

    def _run_jobs_shadow(self, jobs: Sequence[ScriptVerificationJob]) -> list[ScriptError | None]:
        """SHADOW_RUST mode: Python is authoritative; Rust runs the same jobs and any per-job category mismatch
        is logged and counted. Always returns/raises the Python outcome."""
        # Python pass, replicating the serial loop: stop at the first non-ScriptError exception.
        python_results: list[ScriptError | None] = []
        python_raised: BaseException | None = None
        for job in jobs:
            try:
                python_results.append(execute_script_verification_job(job))
            except BaseException as e:
                python_raised = e
                break

        try:
            raw = self._verify_scripts_batch_rust(jobs)
        except Exception:
            self._shadow_mismatches += 1
            logger.error('rust shadow script verification crashed', exc_info=True)
        else:
            self._compare_shadow(jobs, python_results, python_raised, raw)

        if python_raised is not None:
            raise python_raised
        return python_results

    def _compare_shadow(
        self,
        jobs: Sequence[ScriptVerificationJob],
        python_results: list[ScriptError | None],
        python_raised: BaseException | None,
        raw: list[tuple[str, str] | None],
    ) -> None:
        """Compare per-job outcome categories; Python evaluated only ``len(python_results)`` jobs (plus the one
        that raised), so later jobs are not compared."""
        python_categories = [_python_outcome_category(result) for result in python_results]
        if python_raised is not None:
            python_categories.append(_python_outcome_category(python_raised))
        for index, python_category in enumerate(python_categories):
            rust_item = raw[index]
            rust_category = 'valid' if rust_item is None else rust_item[0]
            if python_category == rust_category:
                continue
            self._shadow_mismatches += 1
            job = jobs[index]
            logger.error(
                'rust shadow script verification mismatch',
                input_index=job.input_index,
                python_category=python_category,
                rust_category=rust_category,
                rust_message=None if rust_item is None else rust_item[1],
                input_data=job.input_data.hex(),
                output_script=job.output_script.hex(),
                sighash_all_data=job.sighash_all_data.hex(),
                tx_timestamp=job.tx_timestamp,
                spent_output_value=job.spent_output_value,
                opcodes_version=int(job.opcodes_version),
            )
