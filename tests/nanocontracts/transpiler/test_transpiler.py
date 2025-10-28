#  Copyright 2025 Hathor Labs
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

from textwrap import dedent
from typing import Any

import pytest

from hathor.nanocontracts.transpiler import run


def test_single_const_value() -> None:
    _test_success(
        code=f'{2**256-1}',
        available_gas=3,
        expected_result=2 ** 256 - 1,
        expected_gas=0,
    )


def test_binary_op_add() -> None:
    # the __identity__ function is used to prevent the interpreter from optimizing out the operation
    _test_success(
        code='__identity__(2) + 3',
        available_gas=10,
        expected_result=5,
        expected_gas=1,
    )

    _test_success(
        code='__identity__(1) + __identity__(2) + 3',
        available_gas=100,
        expected_result=6,
        expected_gas=85,
    )

    _test_fail(
        code='__identity__(2) + 3',
        available_gas=2,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )


def test_binary_op_multiply() -> None:
    _test_success(
        code='__identity__(2) * 3',
        available_gas=10,
        expected_result=6,
        expected_gas=1,
    )

    _test_fail(
        code='__identity__(2) * 3',
        available_gas=4,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )


def test_binary_op_power() -> None:
    _test_success(
        code='__identity__(2)**32',
        available_gas=100,
        expected_result=2**32,
        expected_gas=91,
    )

    # if we don't have enough gas it will raise before the size check,
    # that is, before the expression is evaluated
    _test_fail(
        code='__identity__(2)**256',
        available_gas=0,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )

    # here, x=32**32 is evaluated, but 2**x is not
    _test_fail(
        code='2**32**32',
        available_gas=0,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )

    # using it in a range fails too
    _test_fail(
        code='range(2**32**32)',
        available_gas=0,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )


def test_infinite_multiply() -> None:
    code = dedent('''
        x = 2
        while True:
            x = x * 2
    ''')

    # we quickly run out of gas as we spend 5 on each loop run
    _test_fail(
        code=code,
        available_gas=10,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )


def test_infinite_string() -> None:
    code = dedent('''
        x = 'a'
        while True:
            x = x * 2
    ''')

    # we quickly run out of gas as we spend 5 on each loop run
    _test_fail(
        code=code,
        available_gas=10,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )

def test_infinite_array() -> None:
    # x = ['a']; while True: x = x + x
    code = dedent('''
        x = ['a']
        while True:
            x = x + x
    ''')

    # we quickly run out of gas as we spend 3 on each loop run
    _test_fail(
        code=code,
        available_gas=10,
        exception=RuntimeError,
        message='out of gas! remaining: -1',
    )


def _test_success(*, code: str, available_gas: int, expected_result: Any, expected_gas: int) -> None:
    result, remaining_gas = run(code, available_gas=available_gas)
    assert result == expected_result, f'invalid result: {result} != {expected_result}'
    assert remaining_gas == expected_gas, f'invalid gas: {remaining_gas} != {expected_gas}'


def _test_fail(*, code: str, available_gas: int, exception: type[Exception], message: str) -> None:
    with pytest.raises(exception) as e:
        run(code, available_gas=available_gas)
    assert str(e.value) == message
