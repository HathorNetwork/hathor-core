# Copyright 2026 Hathor Labs
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

import builtins
import unittest

import pytest

from hathorlib.nanocontracts.custom_builtins import DISABLED_BUILTINS, get_exec_builtins
from hathorlib.nanocontracts.exception import NCDisabledBuiltinError


class CustomBuiltinsTestCase(unittest.TestCase):
    def test_get_exec_builtins_is_cached(self) -> None:
        # Identity check pins the lazy-init contract: subsequent calls must return the same dict instance.
        first = get_exec_builtins()
        second = get_exec_builtins()
        assert first is second

    def test_exec_builtins_exposes_safe_callables(self) -> None:
        exec_builtins = get_exec_builtins()
        assert exec_builtins['abs'] is builtins.abs
        assert exec_builtins['len'] is builtins.len
        assert exec_builtins['isinstance'] is builtins.isinstance

    def test_exec_builtins_exposes_only_exception_subclasses(self) -> None:
        # No non-Exception BaseException subclass (BaseException, GeneratorExit, KeyboardInterrupt, SystemExit)
        # may leak into the blueprint env — they bubble up past Nano's catch and crash the full node.
        exec_builtins = get_exec_builtins()
        for name, value in exec_builtins.items():
            if isinstance(value, type) and issubclass(value, BaseException):
                assert issubclass(value, Exception), f'non-Exception subclass leaked into exec builtins: {name}'

    def test_disabled_builtins_are_replaced_with_disabled_func(self) -> None:
        exec_builtins = get_exec_builtins()
        for name in DISABLED_BUILTINS:
            assert name in exec_builtins
            assert exec_builtins[name] is not getattr(builtins, name, None)

    def test_disabled_builtin_raises_when_called(self) -> None:
        exec_builtins = get_exec_builtins()
        with pytest.raises(NCDisabledBuiltinError):
            exec_builtins['eval']('1 + 1')
