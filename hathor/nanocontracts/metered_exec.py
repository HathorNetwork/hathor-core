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

import sys
from typing import Any, Callable, TypeVar, TypeVarTuple, Unpack, cast

from structlog import get_logger

from hathor.nanocontracts.on_chain_blueprint import PYTHON_CODE_COMPAT_VERSION

logger = get_logger()

_T = TypeVar('_T')
_Ts = TypeVarTuple('_Ts')

# Filename used for all blueprint code compilation.
# This is registered with the sandbox for scope tracking.
BLUEPRINT_FILENAME = '<blueprint>'


class MeteredExecutor:
    """Executor that enforces CPython sandbox limits during code execution.

    This class configures and manages the CPython sandbox limits that are enforced
    during blueprint execution. Limits can be modified via class attributes for testing.

    Sandbox limits enforce:
    - Statement execution limits (max_statements)
    - Memory allocation limits (max_allocations)
    - Object size limits (integers, strings, lists, dicts, etc.)
    - Type restrictions (forbids float and complex)

    Class Attributes:
        max_int_digits: Maximum digits allowed in integers (~10^N)
        max_str_length: Maximum string length in characters
        max_bytes_length: Maximum bytes length
        max_list_size: Maximum number of items in a list
        max_dict_size: Maximum number of entries in a dict
        max_set_size: Maximum number of items in a set
        max_tuple_size: Maximum number of items in a tuple
        max_statements: Maximum statements per execution scope
        max_allocations: Maximum allocations per execution scope
        allow_float: Whether float type is allowed
        allow_complex: Whether complex type is allowed
    """

    # Size limits (prevent DoS via large objects)
    max_int_digits: int = 100           # ~10^900, prevents huge integer DoS
    max_str_length: int = 1_000_000     # 1M chars
    max_bytes_length: int = 1_000_000   # 1M bytes
    max_list_size: int = 100_000        # 100K items
    max_dict_size: int = 100_000        # 100K entries
    max_set_size: int = 100_000         # 100K items
    max_tuple_size: int = 100_000       # 100K items

    # Execution limits (scoped to blueprint code)
    max_statements: int = 1_000_000   # 1M statements
    max_allocations: int = 100_000    # 100K allocations

    # Type restrictions (security hardening)
    allow_float: bool = False
    allow_complex: bool = False

    # Track whether sandbox has been initialized
    _sandbox_initialized: bool = False

    __slots__ = ('_debug',)

    def __init__(self) -> None:
        self._debug = False
        self._ensure_sandbox_initialized()

    @classmethod
    def _ensure_sandbox_initialized(cls) -> None:
        """Initialize sandbox limits if not already done.

        This is called automatically on first MeteredExecutor instantiation.
        The sandbox is configured globally, so this only needs to happen once.
        After initialization, the sandbox is suspended until exec/call resumes it.
        """
        if cls._sandbox_initialized:
            return

        cls._apply_sandbox_limits()
        # Start with limits suspended (will resume during exec/call)
        # This is only called once during initialization
        sys.sandbox.suspend()
        cls._sandbox_initialized = True

    @classmethod
    def _apply_sandbox_limits(cls) -> None:
        """Apply the current sandbox limit settings.

        This method configures the CPython sandbox with the current class attribute values.
        Call this after modifying limits (e.g., in tests) to apply the changes.

        IMPORTANT: Sandbox limits must be set while NOT suspended to take effect.
        This method handles the suspend state automatically.
        """
        # CPython sandbox quirk: limits must be set while NOT suspended
        was_suspended = sys.sandbox.suspended
        if was_suspended:
            sys.sandbox.resume()

        try:
            sys.sandbox.set_limits(
                max_int_digits=cls.max_int_digits,
                max_str_length=cls.max_str_length,
                max_bytes_length=cls.max_bytes_length,
                max_list_size=cls.max_list_size,
                max_dict_size=cls.max_dict_size,
                max_set_size=cls.max_set_size,
                max_tuple_size=cls.max_tuple_size,
                max_statements=cls.max_statements,
                max_allocations=cls.max_allocations,
                allow_float=cls.allow_float,
                allow_complex=cls.allow_complex,
            )

            # Register the blueprint filename for scope tracking (idempotent)
            sys.sandbox.add_filename(BLUEPRINT_FILENAME)
        finally:
            # Restore suspend state
            if was_suspended:
                sys.sandbox.suspend()

    @classmethod
    def reset_sandbox_limits(cls) -> None:
        """Reset sandbox limits to default values and re-apply them.

        This is useful in tests to restore default limits after modification.
        """
        cls.max_int_digits = 100
        cls.max_str_length = 1_000_000
        cls.max_bytes_length = 1_000_000
        cls.max_list_size = 100_000
        cls.max_dict_size = 100_000
        cls.max_set_size = 100_000
        cls.max_tuple_size = 100_000
        cls.max_statements = 1_000_000
        cls.max_allocations = 100_000
        cls.allow_float = False
        cls.allow_complex = False
        cls._apply_sandbox_limits()

    def exec(self, source: str, /) -> dict[str, Any]:
        """Execute source code with sandbox limits enforced.

        This is equivalent to `exec(source)` but with execution metering and memory limiting.
        The sandbox limits are only enforced for code compiled with the blueprint filename.

        Args:
            source: Python source code to execute

        Returns:
            Execution environment (globals dict) with __builtins__ removed

        Raises:
            Various sandbox exceptions (OverflowError, TypeError, MemoryError, RuntimeError)
            when limits are exceeded.
        """
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS

        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
        }

        # Reset counters before each execution
        sys.sandbox.reset_counts()

        # Resume limits for compile and exec
        sys.sandbox.resume()
        try:
            code = compile(
                source=source,
                filename=BLUEPRINT_FILENAME,
                mode='exec',
                flags=0,
                dont_inherit=True,
                optimize=0,
                _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
            )
            # XXX: SECURITY: `code` and `env` have proper restrictions at this point
            exec(code, env)
        finally:
            # Suspend limits after execution
            sys.sandbox.suspend()

        del env['__builtins__']
        return env

    def call(self, func: Callable[[Unpack[_Ts]], _T], /, *, args: tuple[Unpack[_Ts]], reset_counters: bool = True) -> _T:
        """Call a function with sandbox limits enforced.

        This is equivalent to `func(*args)` but with execution metering and memory limiting.

        Args:
            func: Callable to invoke
            args: Positional arguments tuple
            reset_counters: If True, reset sandbox counters before execution.
                           Set to False for nested calls to accumulate statement counts.

        Returns:
            Function return value

        Raises:
            NCFail: If execution fails or any sandbox limit is exceeded
        """
        from hathor import NCFail
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS

        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
            '__func__': func,
            '__args__': args,
            '__result__': None,
        }

        # Only reset counters if explicitly requested (top-level calls)
        if reset_counters:
            sys.sandbox.reset_counts()

        # Resume limits for compile and exec
        sys.sandbox.resume()
        try:
            code = compile(
                source='__result__ = __func__(*__args__)',
                filename=BLUEPRINT_FILENAME,
                mode='exec',
                flags=0,
                dont_inherit=True,
                optimize=0,
                _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
            )

            try:
                exec(code, env)
            except NCFail:
                # Blueprint explicitly raised NCFail, preserve it
                raise
            except Exception as e:
                # Sandbox exceptions (OverflowError, TypeError, MemoryError, RuntimeError)
                # and any other exceptions get converted to NCFail
                raise NCFail from e
        finally:
            # Suspend limits after execution
            sys.sandbox.suspend()

        return cast(_T, env['__result__'])
