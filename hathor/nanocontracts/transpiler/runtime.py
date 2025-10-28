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

import math
from typing import Any

"""
This module provides auxiliary functions to be used by the OCB transpiler.

Runtime functions start with __ and are supposed to be called during Nano Contract runtime using one of the provided
callers from the transpiler module: _call_function_with_tos() or _call_function_with_args().
"""

# The maximum size in bytes allowed for a single item in the Python interpreter stack.
# This is not the real size of the Python object, but rather a size representation of its value.
# For ints for example, 32 bytes is equivalent to an int256.
MAX_STACK_ITEM_SIZE: int = 32


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


def __check_max_stack_item_size__(item: Any) -> Any:
    """Raise an exception if item is larger than the allowed max stack item size, return the item otherwise."""
    size = _calc_stack_item_size(item)
    if size > MAX_STACK_ITEM_SIZE:
        raise RuntimeError(f'value too large: {item} ({type(item).__name__})')
    return item


def __check_gas__(remaining_gas: int) -> None:
    """Raise an exception if remaining_gas is below zero."""
    if remaining_gas < 0:
        raise RuntimeError(f'out of gas! remaining: {remaining_gas}')


def __calc_power_gas__(exponent: int) -> int:
    """
    Calculate a dynamic gas cost for a power operation, given its exponent.

    This is the same formula as used by EVM:
    - https://ethereum.org/en/developers/docs/evm/opcodes/
    - https://github.com/wolflo/evm-opcodes/blob/main/gas.md#a1-exp
    - https://evm-from-scratch.xyz/content/07a_opcodes/02_math
    """
    size_in_bytes = 1 if exponent == 0 else _size_in_bytes(exponent)
    return 10 + 50 * size_in_bytes


# A list of functions to be made available for the transpiler during NC runtime.
TRANSPILER_RUNTIME_FUNCTIONS = [
    __identity__,
    __inspect__,
    __check_max_stack_item_size__,
    __check_gas__,
    __calc_power_gas__,
]


def _size_in_bytes(number: int) -> int:
    """Calculate the minimum size in bytes required to store a number."""
    return math.ceil(number.bit_length() / 8)


def _calc_stack_item_size(item: Any) -> int:
    """Calculate the stack size for an item according to its type."""
    match item:
        case int():
            return _size_in_bytes(item)
        case str():
            return len(item.encode('utf8'))
        case list():
            return sum(_calc_stack_item_size(e) for e in item)
        case _:
            raise NotImplementedError(f'unsupported stack item type: {item} ({type(item).__name__})')
