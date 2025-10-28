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

import dis
from enum import StrEnum, auto
from typing import Any, Iterator

from bytecode import BinaryOp, Bytecode, Instr, Label

from hathor.nanocontracts.transpiler.runtime import (
    TRANSPILER_RUNTIME_FUNCTIONS,
    __check_gas__,
)

"""
This module contains functions that implement a Python bytecode transpilation to be used in on-chain Blueprints.

Given a Python bytecode, the transpile() function will substitute each instruction adding checks such gas consumption.
"""

# The global name used to store the available gas in NC runtime.
GAS_NAME: str = '__gas__'

# The local name used to store the top of the stack (TOS) in NC runtime.
TOS_NAME: str = '__tos__'

# A list of names that must be blacklisted from the OCB code AST.
TRANSPILER_NAME_BLACKLIST = [GAS_NAME, TOS_NAME]


class InstrName(StrEnum):
    """Name of Python bytecode instructions"""
    CACHE = auto()
    POP_TOP = auto()
    PUSH_NULL = auto()
    NOP = auto()
    UNARY_POSITIVE = auto()
    UNARY_NEGATIVE = auto()
    UNARY_NOT = auto()
    UNARY_INVERT = auto()
    BINARY_SUBSCR = auto()
    GET_LEN = auto()
    PUSH_EXC_INFO = auto()
    STORE_SUBSCR = auto()
    DELETE_SUBSCR = auto()
    GET_ITER = auto()
    GET_YIELD_FROM_ITER = auto()
    LOAD_BUILD_CLASS = auto()
    LOAD_ASSERTION_ERROR = auto()
    LIST_TO_TUPLE = auto()
    RETURN_VALUE = auto()
    IMPORT_STAR = auto()
    SETUP_ANNOTATIONS = auto()
    YIELD_VALUE = auto()
    PREP_RERAISE_STAR = auto()
    POP_EXCEPT = auto()
    STORE_NAME = auto()
    DELETE_NAME = auto()
    UNPACK_SEQUENCE = auto()
    FOR_ITER = auto()
    UNPACK_EX = auto()
    STORE_ATTR = auto()
    DELETE_ATTR = auto()
    STORE_GLOBAL = auto()
    DELETE_GLOBAL = auto()
    SWAP = auto()
    LOAD_CONST = auto()
    LOAD_NAME = auto()
    BUILD_TUPLE = auto()
    BUILD_LIST = auto()
    BUILD_SET = auto()
    BUILD_MAP = auto()
    LOAD_ATTR = auto()
    COMPARE_OP = auto()
    IMPORT_NAME = auto()
    IMPORT_FROM = auto()
    JUMP_FORWARD = auto()
    JUMP_IF_FALSE_OR_POP = auto()
    JUMP_IF_TRUE_OR_POP = auto()
    POP_JUMP_FORWARD_IF_FALSE = auto()
    POP_JUMP_FORWARD_IF_TRUE = auto()
    LOAD_GLOBAL = auto()
    IS_OP = auto()
    CONTAINS_OP = auto()
    RERAISE = auto()
    COPY = auto()
    BINARY_OP = auto()
    SEND = auto()
    LOAD_FAST = auto()
    STORE_FAST = auto()
    DELETE_FAST = auto()
    POP_JUMP_FORWARD_IF_NOT_NONE = auto()
    POP_JUMP_FORWARD_IF_NONE = auto()
    RAISE_VARARGS = auto()
    MAKE_FUNCTION = auto()
    BUILD_SLICE = auto()
    JUMP_BACKWARD_NO_INTERRUPT = auto()
    MAKE_CELL = auto()
    LOAD_CLOSURE = auto()
    LOAD_DEREF = auto()
    STORE_DEREF = auto()
    DELETE_DEREF = auto()
    JUMP_BACKWARD = auto()
    CALL_FUNCTION_EX = auto()
    EXTENDED_ARG = auto()
    LIST_APPEND = auto()
    SET_ADD = auto()
    MAP_ADD = auto()
    LOAD_CLASSDEREF = auto()
    COPY_FREE_VARS = auto()
    RESUME = auto()
    FORMAT_VALUE = auto()
    BUILD_CONST_KEY_MAP = auto()
    BUILD_STRING = auto()
    LOAD_METHOD = auto()
    LIST_EXTEND = auto()
    SET_UPDATE = auto()
    DICT_MERGE = auto()
    DICT_UPDATE = auto()
    PRECALL = auto()
    CALL = auto()
    KW_NAMES = auto()
    POP_JUMP_BACKWARD_IF_NOT_NONE = auto()
    POP_JUMP_BACKWARD_IF_NONE = auto()
    POP_JUMP_BACKWARD_IF_FALSE = auto()
    POP_JUMP_BACKWARD_IF_TRUE = auto()

    def to_instr(self, *args: Any) -> Instr:
        """Convert this instance to an Instr with the provided args."""
        return Instr(self.name, *args)


def run(raw_code: str, *, available_gas: int) -> tuple[Any, int]:
    """
    Eval a code string using the available_gas. Returns the result of the eval and the remaining gas.
    """
    std_bytecode = dis.Bytecode(raw_code)
    lib_bytecode = Bytecode.from_code(std_bytecode.codeobj)
    transpiled_bytecode = transpile(lib_bytecode)
    code_obj = transpiled_bytecode.to_code()

    print()
    print('--- raw code ---------------------------------------------------------------------------------------------')
    print(repr(raw_code))
    print('--- original bytecode ------------------------------------------------------------------------------------')
    print(std_bytecode.dis())
    print('--- transpiled bytecode ----------------------------------------------------------------------------------')
    dis.dis(code_obj, depth=0)
    print('----------------------------------------------------------------------------------------------------------')

    runtime_functions = {f.__name__: f for f in TRANSPILER_RUNTIME_FUNCTIONS}
    globals_dict: dict[str, Any] = {GAS_NAME: available_gas, **runtime_functions}
    result = eval(code_obj, globals_dict)
    remaining_gas = globals_dict[GAS_NAME]

    print('run output:', result)
    print('remaining gas:', remaining_gas)
    print()
    return result, remaining_gas


def transpile(bytecode: Bytecode) -> Bytecode:
    """Transpile a Bytecode, adding instructions for handling checks and gas consumption."""
    instructions = _transpile_instructions(bytecode)
    return Bytecode(list(instructions))


def _transpile_instructions(bytecode: Bytecode) -> Iterator[Instr | Label]:
    """Transpile a Bytecode's instructions, yielding added instructions for handling checks and gas consumption."""
    for instruction in bytecode:
        match instruction:
            case Instr():
                yield from _update_and_check_gas(instruction)
                yield instruction
            case Label():
                yield instruction
            case _:
                raise NotImplementedError(f'unsupported instruction type: {instruction}')


def _load_gas_expense(_instruction: Instr) -> Iterator[Instr]:
    """Load the gas expense on TOS for the provided instruction."""
    yield InstrName.LOAD_CONST.to_instr(1)


def _update_and_check_gas(instruction: Instr) -> Iterator[Instr]:
    """Update the remaining gas and check if the operation is valid."""
    # TODO: In theory I should be able to get the __gas__ value from globals() in a runtime function
    #  instead of programming bytecodes, but for some reason it didn't work.

    # First, load the expense and the available gas to the stack. We need the _load_gas_expense
    # to be called before loading the available gas, so it has access to the original TOS.
    yield from _load_gas_expense(instruction)
    yield InstrName.LOAD_GLOBAL.to_instr((False, GAS_NAME))

    # Perform the subtraction and invert it, that is `-(expense - available)`.
    # This is done to put the expense before on the stack, as explained above.
    yield InstrName.BINARY_OP.to_instr(BinaryOp.SUBTRACT)
    yield InstrName.UNARY_NEGATIVE.to_instr()

    # Update the global var, put it back on the stack for checking, and pop the returned None.
    yield InstrName.STORE_GLOBAL.to_instr(GAS_NAME)
    yield InstrName.LOAD_GLOBAL.to_instr((False, GAS_NAME))
    yield from _call_function_with_tos(__check_gas__.__name__)
    yield InstrName.POP_TOP.to_instr()


def _call_function_with_tos(function_name: str) -> Iterator[Instr]:
    """
    Call a function with a function_name from the global scope, consuming TOS as its single argument.
    The return value is put on TOS.
    """
    yield InstrName.STORE_NAME.to_instr(TOS_NAME)
    yield InstrName.LOAD_GLOBAL.to_instr((True, function_name))
    yield InstrName.LOAD_NAME.to_instr(TOS_NAME)
    yield InstrName.PRECALL.to_instr(1)
    yield InstrName.CALL.to_instr(1)
    yield InstrName.DELETE_NAME.to_instr(TOS_NAME)
