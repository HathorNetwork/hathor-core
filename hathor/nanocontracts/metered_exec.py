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

import dis
import sys
import tracemalloc
from enum import Enum
from types import CodeType, FrameType, TracebackType
from typing import Any, Callable, ParamSpec, TypeAlias, TypeVar, cast

from structlog import get_logger
from typing_extensions import Self

from hathor.nanocontracts.on_chain_blueprint import PYTHON_CODE_COMPAT_VERSION

logger = get_logger()

_T = TypeVar('_T')
_P = ParamSpec('_P')
_EventName: TypeAlias = str
_TraceFunction: TypeAlias = Callable[[FrameType, _EventName, Any], '_TraceFunction | None']


# https://docs.python.org/3/library/sys.html#sys.settrace
# 110 opcodes
# [x for x in dis.opname if not x.startswith('<')]
# TODO: cost for each opcode
FUEL_COST_MAP = [1] * 256


def _compile_compat(source: str) -> CodeType:
    return compile(
        source=source,
        filename='<blueprint>',
        mode='exec',
        flags=0,
        dont_inherit=True,
        optimize=0,
        _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
    )


class OutOfFuelError(RuntimeError):
    """Raised when an execution exceeds the CPU-cycle limit"""


class OutOfMemoryError(MemoryError):
    """Raised when an execution exceeds the memory limit"""


class MeteredExecutor:
    """Used measure and limit the execution of method calls and code exec.
    """
    __slots__ = ('_fuel', '_memory_limit', '_debug', '_no_measure')

    def __init__(self, fuel: int, memory_limit: int, *, _no_measure: bool = False) -> None:
        self._fuel = fuel
        self._memory_limit = memory_limit
        self._debug = False
        self._no_measure = _no_measure

    def get_fuel(self) -> int:
        """Unitless amount of remaining CPU-cycle fuel."""
        return self._fuel

    def get_memory_limit(self) -> int:
        """Byte amount of the maximum memory allowed to be used during execution."""
        return self._memory_limit

    def _metered_context(self) -> _MeteredExecutionContext:
        return _MeteredExecutionContext(self)

    def __exec(self, code: CodeType, env: dict[str, Any]) -> None:
        """Do not call this method from outside this calss."""
        # XXX: SECURITY: `code` and `env` need the proper restrictions by this point
        if self._no_measure:
            exec(code, env)
        else:
            with self._metered_context():
                exec(code, env)

    def exec(self, source: str, /) -> dict[str, Any]:
        """ This is equivalent to `exec(source)` but with execution metering and memory limiting.
        """
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS
        code = _compile_compat(source)
        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
        }
        self.__exec(code, env)
        del env['__builtins__']
        return env

    def call(self, func: Callable[_P, _T], /, *, args: _P.args) -> _T:
        """ This is equivalent to `func(*args, **kwargs)` but with execution metering and memory limiting.
        """
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS
        code = _compile_compat('__result__ = __func__(*__args__)')
        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
            '__func__': func,
            '__args__': args,
            '__result__': None,
        }
        self.__exec(code, env)
        return cast(_T, env['__result__'])


class _ContextState(Enum):
    """ Represents the state of a _MeteredExecutionContext.

    Transitions:
    -> NotStarted
    NotStarted -> Started
    Started -> Paused
    Paused -> Started
    Started -> Stopped
    Stopped: final
    """
    NotStarted = 0
    Started = 1
    Paused = 2
    Stopped = 3


class _MeteredExecutionContext:
    """ Internal class that serves as a context manager to measure execution cycles/memory.

    This class contains the actual implementation that starts/stops the tracing of OP code execution in the Python's
    VM, starts/stops tracemalloc for tracking memory and disassembles OP calls before they are executed to measure CPU
    usage.
    """
    # Class-level flag to prevent nesting
    _active_instance_stack: list[_MeteredExecutionContext] = []

    def __init__(self, executor: MeteredExecutor) -> None:
        self._executor: MeteredExecutor = executor
        self._accumulated_memory: int = 0
        self._start_memory: int = 0
        self._state: _ContextState = _ContextState.NotStarted

    def __enter__(self) -> Self:
        assert self._state is _ContextState.NotStarted

        # Check if there already is an active instance
        if _MeteredExecutionContext._active_instance_stack:
            top_context = _MeteredExecutionContext._active_instance_stack[-1]
            top_context.pause()

        _MeteredExecutionContext._active_instance_stack.append(self)

        self._register_hooks()
        self._state = _ContextState.Started

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None, /
    ) -> None:
        self._clear_hooks()
        prev_state = self._state
        self._state = _ContextState.Stopped

        # Clear the class-level flag to allow future instances
        assert _MeteredExecutionContext._active_instance_stack.pop() is self

        if _MeteredExecutionContext._active_instance_stack:
            top_context = _MeteredExecutionContext._active_instance_stack[-1]
            top_context.resume()

        # Leave this to the end, in case of any bugs
        assert prev_state is _ContextState.Started

    def pause(self) -> None:
        """ Can be used to stack another metered context.

        The current context MUST be paused BEFORE the next one is started, and AFTER the context exits it MUST be
        resumed.
        """
        assert self._state is _ContextState.Started
        new_start_memory, _ = tracemalloc.get_traced_memory()
        self._clear_hooks()
        self._accumulated_memory += new_start_memory - self._start_memory
        self._start_memory = new_start_memory
        self._state = _ContextState.Paused

    def resume(self) -> None:
        """ Resume tracking: once pause is called tracking won't happened until resume is called.
        """
        assert self._state is _ContextState.Paused
        self._register_hooks()
        self._state = _ContextState.Started

    def _register_hooks(self) -> None:
        """Handle the registering of opcode and memory tracing calling global functions."""
        assert self._state in {_ContextState.NotStarted, _ContextState.Paused}

        # Check if tracemalloc is already running
        if tracemalloc.is_tracing():
            raise RuntimeError('tracemalloc is already started by another component')

        # Check if sys.settrace is already in use
        if sys.gettrace() is not None:
            raise RuntimeError('Another trace function is already set')

        # Start tracemalloc and initialize the starting memory
        tracemalloc.start()
        self._start_memory, _ = tracemalloc.get_traced_memory()

        # Set the trace function
        sys.settrace(self._trace_calls)

    def _clear_hooks(self) -> None:
        """Undo what self._register_hooks() does so the global state is consistent."""
        # XXX: don't assert the state now, because if there's a bug it will go wrong
        if self._state is not _ContextState.Started:
            logger.error('invalid state', expected=_ContextState.Started, found=self._state)

        # Remove the trace function and stop tracemalloc
        sys.settrace(None)
        tracemalloc.stop()

    def _trace_calls(self, frame: FrameType, event: _EventName, arg: Any) -> _TraceFunction | None:
        """This method is passed to sys.settrace to track opcode execution."""
        # trace the opcodes so we can have accurate counting
        frame.f_trace_opcodes = True

        # Check memory allocation on each call or return, which are enough to trace allocations
        if event in {'call', 'return'}:
            current_memory, _ = tracemalloc.get_traced_memory()
            used_memory = current_memory - self._start_memory + self._accumulated_memory
            memory_limit = self._executor.get_memory_limit()
            if self._executor._debug:
                logger.debug(f'memory {event=} {used_memory=} {memory_limit=}')
            if used_memory > memory_limit:
                # Clear trace and raise an exception if limit is exceeded
                sys.settrace(None)
                raise OutOfMemoryError(f'Memory limit of {memory_limit} bytes exceeded')

        # https://docs.python.org/3/library/dis.html
        # https://docs.python.org/3/reference/datamodel.html#frame-objects
        # https://docs.python.org/3/reference/datamodel.html#code-objects
        if event in {'opcode', 'line'}:
            bytecode = frame.f_code.co_code[frame.f_lasti]
            opcode_name = dis.opname[bytecode]
            cost = FUEL_COST_MAP[bytecode]
            self._executor._fuel -= cost
            fuel = self._executor._fuel
            if self._executor._debug:
                logger.debug(f'opcode {opcode_name} {cost=} {fuel=}')

        # https://docs.python.org/3/reference/datamodel.html#frame.f_trace_opcodes
        # when tracing opcodes, we should only raise an exception on a line event
        if event == 'line':
            if self._executor._fuel < 0:
                sys.settrace(None)
                raise OutOfFuelError

        return self._trace_calls
