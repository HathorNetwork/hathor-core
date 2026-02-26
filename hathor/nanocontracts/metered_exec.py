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

from typing import TYPE_CHECKING, Any, Callable, TypeVar, TypeVarTuple, Unpack, cast

from structlog import get_logger

from hathor.nanocontracts.on_chain_blueprint import PYTHON_CODE_COMPAT_VERSION
from hathor.nanocontracts.sandbox import (
    BLUEPRINT_FILENAME,
    DISABLED_CONFIG,
    SANDBOX_AVAILABLE,
    PyCF_SANDBOX_COUNT,
    SandboxConfig,
)

if TYPE_CHECKING:
    from types import TracebackType

logger = get_logger()

_T = TypeVar('_T')
_Ts = TypeVarTuple('_Ts')


class MeteredExecutor:
    """Executor that enforces CPython sandbox limits during code execution.

    IMPORTANT: Config is set at __init__ and is IMMUTABLE for the lifetime
    of the executor. There is no setter - create a new executor for different config.
    SandboxConfig is a frozen dataclass, ensuring the values cannot change.

    This class manages sandbox lifecycle via start()/end() methods. The typical
    usage pattern is:

        executor = MeteredExecutor(config=sandbox_config)
        executor.start()  # Enable sandbox
        try:
            result = executor.call(func, args=args)
        finally:
            executor.end()  # Suspend sandbox

    Or using context manager:

        with MeteredExecutor(config=sandbox_config) as executor:
            result = executor.call(func, args=args)

    If config.is_enabled is False, code will be executed without sandbox restrictions.
    When config.is_enabled is True, the system must have a Python build with sandbox
    support (version suffix '-sandbox'), otherwise SandboxRequiredButNotAvailable
    will be raised.
    """

    __slots__ = ('_config', '_debug', '_active')

    def __init__(self, config: SandboxConfig = DISABLED_CONFIG) -> None:
        """Initialize the MeteredExecutor.

        Args:
            config: Sandbox configuration. Stored as-is (SandboxConfig is frozen/immutable).
                   Once set, cannot be changed - create a new executor for different config.
                   If config.is_enabled is False, code will be executed without sandbox restrictions.

        Raises:
            SandboxRequiredButNotAvailable: If config.is_enabled is True but sys.sandbox is not available.
        """
        self._config: SandboxConfig = config
        self._debug = False
        self._active = False
        config.check_available()

    @property
    def config(self) -> SandboxConfig:
        """Read-only access to the sandbox config."""
        return self._config

    @property
    def active(self) -> bool:
        """Whether the sandbox is currently active (started but not ended)."""
        return self._active

    def start(self) -> None:
        """Enable sandbox and apply configuration.

        Call at entry points (create_contract, call_public_method, call_view_method).
        The config set at __init__ is applied here.
        """
        self._config.enable()
        self._config.apply()
        self._config.reset_counts()
        self._active = True

    def end(self) -> None:
        """Suspend sandbox and clean up.

        Call after execution completes (in finally block).
        """
        self._config.reset()
        self._active = False

    def __enter__(self) -> 'MeteredExecutor':
        """Context manager entry - calls start()."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: 'TracebackType | None',
    ) -> None:
        """Context manager exit - calls end()."""
        self.end()

    def reset_counters(self) -> None:
        """Reset sandbox operation counters.

        This should be called by the Runner at the start of each top-level entry point
        (e.g., create_contract, call_public_method). Does nothing if sandbox is disabled.
        """
        self._config.reset_counts()

    def exec(self, source: str, /) -> dict[str, Any]:
        """Execute source code with sandbox limits enforced.

        REQUIRES: start() must be called before this method when config is provided.

        This is equivalent to `exec(source)` but with execution metering and memory limiting
        when a sandbox config was provided at initialization.

        Args:
            source: Python source code to execute

        Returns:
            Execution environment (globals dict) with __builtins__ removed

        Raises:
            AssertionError: If config is provided but start() was not called.
            Various sandbox exceptions (SandboxOverflowError, SandboxTypeError,
            SandboxMemoryError, SandboxRuntimeError) when limits are exceeded and sandbox is enabled.
        """
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS

        assert self._active, "MeteredExecutor.start() must be called before exec()"

        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
        }

        # Always compile with PyCF_SANDBOX_COUNT when sandbox is available.
        # This ensures the bytecode has sandbox counting instructions, which is
        # required for limits to be enforced when the code is later called through
        # a MeteredExecutor with a config.
        compile_flags = PyCF_SANDBOX_COUNT if SANDBOX_AVAILABLE else 0

        code = compile(
            source=source,
            filename=BLUEPRINT_FILENAME,
            mode='exec',
            flags=compile_flags,
            dont_inherit=True,
            optimize=0,
            _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
        )

        # Verify sandbox is properly configured before execution
        self._config.assert_active()

        # Execute the code - sandbox is already enabled via start()
        # No suspend/resume needed here - that's managed by start()/end()
        exec(code, env)

        del env['__builtins__']
        return env

    def call(
        self,
        func: Callable[[Unpack[_Ts]], _T],
        /,
        *,
        args: tuple[Unpack[_Ts]],
        reset_counters: bool = True,
    ) -> _T:
        """Call a function with sandbox limits enforced.

        REQUIRES: start() must be called before this method when config is provided.

        This is equivalent to `func(*args)` but with execution metering and memory limiting
        when a sandbox config was provided at initialization.

        Args:
            func: Callable to invoke
            args: Positional arguments tuple
            reset_counters: If True, reset sandbox counters before execution.
                           Set to False for nested calls to accumulate operation counts.
                           Only applies when sandbox is enabled.

        Returns:
            Function return value

        Raises:
            AssertionError: If config is provided but start() was not called.
            NCFail: If execution fails or any sandbox limit is exceeded (when sandbox is enabled)
        """
        from hathor import NCFail
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS

        assert self._active, "MeteredExecutor.start() must be called before call()"

        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
            '_nc_func_': func,
            '_nc_args_': args,
            '_nc_result_': None,
        }

        # Reset counters if requested (for top-level calls)
        if reset_counters:
            self._config.reset_counts()

        # Mark bound method's self as mutable for frozen mode
        # This allows the contract to modify its own state while preventing
        # modification of other objects passed in from outside
        bound_self = getattr(func, '__self__', None)
        if bound_self is not None:
            self._config.set_mutable(bound_self)

        # Compile with sandbox counting if available
        compile_flags = PyCF_SANDBOX_COUNT if SANDBOX_AVAILABLE else 0
        code = compile(
            source='_nc_result_ = _nc_func_(*_nc_args_)',
            filename=BLUEPRINT_FILENAME,
            mode='exec',
            flags=compile_flags,
            dont_inherit=True,
            optimize=0,
            _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
        )

        # Verify sandbox is properly configured before execution
        self._config.assert_active()

        try:
            # Execute the code - sandbox is already enabled via start()
            # No suspend/resume needed here - that's managed by start()/end()
            exec(code, env)
        except NCFail:
            # Blueprint explicitly raised NCFail, preserve it
            raise
        except BaseException as e:
            # Catch BaseException to prevent malicious contracts from crashing
            # the node via SystemExit, KeyboardInterrupt, or GeneratorExit.
            # Sandbox exceptions (SandboxOverflowError, SandboxTypeError,
            # SandboxMemoryError, SandboxRuntimeError) and any other exceptions
            # get converted to NCFail. Include exception type for debugging.
            exc_info = f'{type(e).__name__}: {e}'
            raise NCFail(f'Execution failed: {exc_info}') from e
        finally:
            # Log execution metrics for observability
            counts = self._config.get_counts()
            if counts:
                logger.debug(
                    'sandbox execution completed',
                    operation_count=counts.get('operation_count', 0),
                    iteration_count=counts.get('iteration_count', 0),
                )

        return cast(_T, env['_nc_result_'])
