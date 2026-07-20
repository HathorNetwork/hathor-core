# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import builtins
import unittest

import pytest

from hathorlib.nanocontracts.custom_builtins import DISABLED_BUILTINS, get_exec_builtins
from hathorlib.nanocontracts.exception import NCDisabledBuiltinError
from hathorlib.token_amount_version import TokenAmountVersion


class CustomBuiltinsTestCase(unittest.TestCase):
    def test_get_exec_builtins_is_cached(self) -> None:
        # Identity check pins the lazy-init contract: subsequent calls must return the same dict instance.
        first = get_exec_builtins(TokenAmountVersion.V2)
        second = get_exec_builtins(TokenAmountVersion.V2)
        assert first is second

    def test_exec_builtins_exposes_safe_callables(self) -> None:
        exec_builtins = get_exec_builtins(TokenAmountVersion.V2)
        assert exec_builtins['abs'] is builtins.abs
        assert exec_builtins['len'] is builtins.len
        assert exec_builtins['isinstance'] is builtins.isinstance

    def test_exec_builtins_exposes_only_exception_subclasses(self) -> None:
        # No non-Exception BaseException subclass (BaseException, GeneratorExit, KeyboardInterrupt, SystemExit)
        # may leak into the blueprint env — they bubble up past Nano's catch and crash the full node.
        exec_builtins = get_exec_builtins(TokenAmountVersion.V2)
        for name, value in exec_builtins.items():
            if isinstance(value, type) and issubclass(value, BaseException):
                assert issubclass(value, Exception), f'non-Exception subclass leaked into exec builtins: {name}'

    def test_disabled_builtins_are_replaced_with_disabled_func(self) -> None:
        exec_builtins = get_exec_builtins(TokenAmountVersion.V2)
        for name in DISABLED_BUILTINS:
            assert name in exec_builtins
            assert exec_builtins[name] is not getattr(builtins, name, None)

    def test_disabled_builtin_raises_when_called(self) -> None:
        exec_builtins = get_exec_builtins(TokenAmountVersion.V2)
        with pytest.raises(NCDisabledBuiltinError):
            exec_builtins['eval']('1 + 1')
