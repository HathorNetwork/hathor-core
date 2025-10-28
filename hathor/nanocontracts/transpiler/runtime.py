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

from typing import Any

"""
This module provides auxiliary functions to be used by the OCB transpiler.

Runtime functions start with __ and are supposed to be called during Nano Contract runtime using one of the provided
callers from the transpiler module: _call_function_with_tos() or _call_function_with_args().
"""


def __identity__(x: Any) -> Any:
    """
    Return the x itself. Useful for transpilation tests, to prevent the interpreter from optimizing out constants.
    """
    return x


def __inspect__(x: Any) -> Any:
    """
    Print x and return it back. Useful for debugging during transpiler development.
    For example, to peek the TOS value without consuming it, use `yield from _call_function_with_tos(__inspect__)`
    """
    print(x)
    return x


def __check_gas__(remaining_gas: int) -> None:
    """Raise an exception if remaining_gas is below zero."""
    if remaining_gas < 0:
        raise RuntimeError(f'out of gas! remaining: {remaining_gas}')


# A list of functions to be made available for the transpiler during NC runtime.
TRANSPILER_RUNTIME_FUNCTIONS = [
    __identity__,
    __inspect__,
    __check_gas__,
]
