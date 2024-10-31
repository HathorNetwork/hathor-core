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

import builtins
from typing import Any, Callable, ParamSpec, TypeVar, cast

from structlog import get_logger

from hathor.nanocontracts.on_chain_blueprint import PYTHON_CODE_COMPAT_VERSION

logger = get_logger()

_T = TypeVar('_T')
_P = ParamSpec('_P')


# https://docs.python.org/3/library/sys.html#sys.settrace
# 110 opcodes
# [x for x in dis.opname if not x.startswith('<')]
# TODO: cost for each opcode
FUEL_COST_MAP = [1] * 256

# list of allowed builtins during execution of an on-chain blueprint code
EXEC_BUILTINS: dict[str, Any] = {
    name: getattr(builtins, name) for name in {
        'False',
        'None',
        'True',
        '__build_class__',
        '__import__',
        '__name__',
        'abs',
        'all',
        'any',
        'ascii',
        'bin',
        'bool',
        'bytearray',
        'bytes',
        'classmethod',
        'complex',
        'dict',
        'divmod',
        'enumerate',
        'filter',
        'float',
        'format',
        'hex',
        'int',
        'iter',
        'len',
        'list',
        'max',
        'min',
        'next',
        'pow',
        'property',
        'range',
        'round',
        'set',
        'slice',
        'staticmethod',
        'str',
        'sum',
        'super',
        'tuple',
        'type',
        'zip',
        'sorted',
        'oct',
        'ord',
        'frozenset',
        'chr',
        'map',
        'hash',
        'callable',
        # These are the ones that were omitted:
        # 'ArithmeticError',
        # 'AssertionError',
        # 'AttributeError',
        # 'BaseException',
        # 'BaseExceptionGroup',
        # 'BlockingIOError',
        # 'BrokenPipeError',
        # 'BufferError',
        # 'BytesWarning',
        # 'ChildProcessError',
        # 'ConnectionAbortedError',
        # 'ConnectionError',
        # 'ConnectionRefusedError',
        # 'ConnectionResetError',
        # 'DeprecationWarning',
        # 'EOFError',
        # 'Ellipsis',
        # 'EncodingWarning',
        # 'EnvironmentError',
        # 'Exception',
        # 'ExceptionGroup',
        # 'FileExistsError',
        # 'FileNotFoundError',
        # 'FloatingPointError',
        # 'FutureWarning',
        # 'GeneratorExit',
        # 'IOError',
        # 'ImportError',
        # 'ImportWarning',
        # 'IndentationError',
        # 'IndexError',
        # 'InterruptedError',
        # 'IsADirectoryError',
        # 'KeyError',
        # 'KeyboardInterrupt',
        # 'LookupError',
        # 'MemoryError',
        # 'ModuleNotFoundError',
        # 'NameError',
        # 'NotADirectoryError',
        # 'NotImplemented',
        # 'NotImplementedError',
        # 'OSError',
        # 'OverflowError',
        # 'PendingDeprecationWarning',
        # 'PermissionError',
        # 'ProcessLookupError',
        # 'RecursionError',
        # 'ReferenceError',
        # 'ResourceWarning',
        # 'RuntimeError',
        # 'RuntimeWarning',
        # 'StopAsyncIteration',
        # 'StopIteration',
        # 'SyntaxError',
        # 'SyntaxWarning',
        # 'SystemError',
        # 'SystemExit',
        # 'TabError',
        # 'TimeoutError',
        # 'TypeError',
        # 'UnboundLocalError',
        # 'UnicodeDecodeError',
        # 'UnicodeEncodeError',
        # 'UnicodeError',
        # 'UnicodeTranslateError',
        # 'UnicodeWarning',
        # 'UserWarning',
        # 'ValueError',
        # 'Warning',
        # 'ZeroDivisionError',
        # '__debug__',
        # '__doc__',
        # '__loader__',
        # '__package__',
        # '__spec__',
        # 'aiter',
        # 'anext',
        # 'breakpoint',
        # 'compile',
        # 'copyright',
        # 'credits',
        # 'delattr',
        # 'dir',
        # 'eval',
        # 'exec',
        # 'exit',
        # 'getattr',
        # 'globals',
        # 'hasattr',
        # 'help',
        # 'id',
        # 'input',
        # 'isinstance',
        # 'issubclass',
        # 'license',
        # 'locals',
        # 'memoryview',
        # 'object',
        # 'open',
        # 'print',
        # 'quit',
        # 'repr',
        # 'reversed',
        # 'setattr',
        # 'vars',
    }
}


class OutOfFuelError(RuntimeError):
    pass


class OutOfMemoryError(MemoryError):
    pass


class MeteredExecutor:
    __slots__ = ('_fuel', '_memory_limit', '_debug')

    def __init__(self, fuel: int, memory_limit: int) -> None:
        self._fuel = fuel
        self._memory_limit = memory_limit
        self._debug = False

    def get_fuel(self) -> int:
        return self._fuel

    def get_memory_limit(self) -> int:
        return self._memory_limit

    def exec(self, source: str, /) -> dict[str, Any]:
        """ This is equivalent to `exec(source)` but with execution metering and memory limiting.
        """
        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
        }
        # XXX: calling compile now makes the exec step consume less fuel
        code = compile(
            source=source,
            filename='<blueprint>',
            mode='exec',
            flags=0,
            dont_inherit=True,
            optimize=0,
            _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
        )
        # XXX: SECURITY: `code` and `env` need the proper restrictions by this point
        exec(code, env)
        del env['__builtins__']
        return env

    def call(self, func: Callable[_P, _T], /, *args: _P.args, **kwargs: _P.kwargs) -> _T:
        """ This is equivalent to `func(*args, **kwargs)` but with execution metering and memory limiting.
        """
        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
            '__func__': func,
            '__args__': args,
            '__kwargs__': kwargs,
            '__result__': None,
        }
        # XXX: calling compile now makes the exec step consume less fuel
        code = compile(
            source='__result__ = __func__(*__args__, **__kwargs__)',
            filename='<blueprint>',
            mode='exec',
            flags=0,
            dont_inherit=True,
            optimize=0,
            _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
        )
        exec(code, env)
        return cast(_T, env['__result__'])
