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

from typing import Any, Callable, TypeVar, TypeVarTuple, Unpack, cast

from structlog import get_logger

from hathor.nanocontracts.on_chain_blueprint import PYTHON_CODE_COMPAT_VERSION

logger = get_logger()

_T = TypeVar('_T')
_Ts = TypeVarTuple('_Ts')


# https://docs.python.org/3/library/sys.html#sys.settrace
# 110 opcodes
# [x for x in dis.opname if not x.startswith('<')]
# TODO: cost for each opcode
FUEL_COST_MAP = [1] * 256


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
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS
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

    def call(self, func: Callable[[Unpack[_Ts]], _T], /, *, args: tuple[Unpack[_Ts]]) -> _T:
        """ This is equivalent to `func(*args, **kwargs)` but with execution metering and memory limiting.
        """
        from hathor import NCFail
        from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS

        env: dict[str, object] = {
            '__builtins__': EXEC_BUILTINS,
            '__func__': func,
            '__args__': args,
            '__result__': None,
        }
        # XXX: calling compile now makes the exec step consume less fuel
        code = compile(
            source='__result__ = __func__(*__args__)',
            filename='<blueprint>',
            mode='exec',
            flags=0,
            dont_inherit=True,
            optimize=0,
            _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
        )

        try:
            exec(code, env)
        except NCFail:
            raise
        except Exception as e:
            # Convert any other exception to NCFail.
            raise NCFail from e

        return cast(_T, env['__result__'])
