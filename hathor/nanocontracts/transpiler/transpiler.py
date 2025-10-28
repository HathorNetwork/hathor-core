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
    __calc_power_gas__,
    __check_gas__,
    __check_max_stack_item_size__,
)

"""
This module contains functions that implement a Python bytecode transpilation to be used in on-chain Blueprints.

Given a Python bytecode, the transpile() function will substitute each instruction adding checks such as stack item
size and gas consumption.
"""

# The global name used to store the available gas in NC runtime.
GAS_NAME: str = '__gas__'

# The local name used to store the top of the stack (TOS) in NC runtime.
TOS_NAME: str = '__tos__'

# A list of names that must be blacklisted from the OCB code AST.
TRANSPILER_NAME_BLACKLIST = [GAS_NAME, TOS_NAME]


class InstrName(StrEnum):
    """Name of Python bytecode instructions"""
    RESUME = auto()
    LOAD_CONST = auto()
    LOAD_NAME = auto()
    STORE_NAME = auto()
    DELETE_NAME = auto()
    LOAD_GLOBAL = auto()
    STORE_GLOBAL = auto()
    PUSH_NULL = auto()
    MAKE_FUNCTION = auto()
    PRECALL = auto()
    CALL = auto()
    UNARY_NEGATIVE = auto()
    BINARY_OP = auto()
    BINARY_SUBSCR = auto()
    POP_TOP = auto()
    NOP = auto()
    JUMP_BACKWARD = auto()
    BUILD_LIST = auto()
    RETURN_VALUE = auto()

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
                # TODO: Should we spend gas for instructions added by ourselves during transpilation? If yes, move this
                yield from _update_and_check_gas(instruction)
                yield from _transpile_instruction(instruction)
            case Label():
                yield instruction
            case _:
                raise NotImplementedError(f'unsupported instruction type: {instruction}')


def _transpile_instruction(instruction: Instr) -> Iterator[Instr]:
    """Transpile a single instruction, possibly yielding more than one new instruction for each original one."""
    match instruction.name.lower():
        case (
            InstrName.RESUME
            | InstrName.LOAD_NAME
            | InstrName.RETURN_VALUE
            | InstrName.PUSH_NULL
            | InstrName.PRECALL
            | InstrName.CALL  # TODO: Maybe we should __check_max_stack_item_size__ for this, too. Review all ops.
            | InstrName.POP_TOP
            | InstrName.BINARY_SUBSCR
            | InstrName.STORE_NAME
            | InstrName.NOP
            | InstrName.JUMP_BACKWARD
            | InstrName.BUILD_LIST
        ):
            yield instruction

        case InstrName.LOAD_CONST:
            yield instruction
            yield from _call_function_with_tos(__check_max_stack_item_size__.__name__)

        case InstrName.BINARY_OP:
            arg = instruction.arg
            assert isinstance(arg, int)
            match arg:
                case BinaryOp.ADD | BinaryOp.MULTIPLY | BinaryOp.POWER:
                    yield instruction
                    yield from _call_function_with_tos(__check_max_stack_item_size__.__name__)
                case _:
                    raise NotImplementedError(f'unsupported BINARY_OP operation: {BinaryOp(arg).name}')

        case _:
            raise NotImplementedError(f'unsupported instruction: {instruction.name}')


def _load_gas_expense(instruction: Instr) -> Iterator[Instr]:
    """Load the gas expense on TOS for the provided instruction."""
    match instruction.name.lower():
        case (
            InstrName.RESUME
            | InstrName.LOAD_NAME
            | InstrName.LOAD_CONST
            | InstrName.RETURN_VALUE
            | InstrName.PUSH_NULL
            | InstrName.PRECALL
            | InstrName.CALL
            | InstrName.POP_TOP
            | InstrName.BINARY_SUBSCR
            | InstrName.STORE_NAME
            | InstrName.NOP
            | InstrName.JUMP_BACKWARD
            | InstrName.BUILD_LIST
        ):
            yield InstrName.LOAD_CONST.to_instr(0)

        case InstrName.BINARY_OP:
            arg = instruction.arg
            assert isinstance(arg, int)
            match arg:
                case BinaryOp.ADD:
                    yield InstrName.LOAD_CONST.to_instr(3)
                case BinaryOp.MULTIPLY:
                    yield InstrName.LOAD_CONST.to_instr(5)
                case BinaryOp.POWER:
                    # __calc_power_gas__ consumes the TOS, so we duplicate it first
                    yield from _duplicate_tos()
                    yield from _call_function_with_tos(__calc_power_gas__.__name__)
                case _:
                    raise NotImplementedError(f'unsupported BINARY_OP operation: {BinaryOp(arg).name}')

        case _:
            raise NotImplementedError(f'unsupported instruction: {instruction.name}')


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


def _duplicate_tos() -> Iterator[Instr]:
    """Duplicate the TOS. Useful before calling functions that consume the TOS."""
    yield InstrName.STORE_NAME.to_instr(TOS_NAME)
    yield InstrName.LOAD_NAME.to_instr(TOS_NAME)
    yield InstrName.LOAD_NAME.to_instr(TOS_NAME)
    yield InstrName.DELETE_NAME.to_instr(TOS_NAME)


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


def _call_function_with_args(function_name: str, *args: Any) -> Iterator[Instr]:
    """Call a function with custom const args. The return value is put on TOS."""
    yield InstrName.LOAD_GLOBAL.to_instr((True, function_name))
    yield from (InstrName.LOAD_CONST.to_instr(arg) for arg in args)
    yield InstrName.PRECALL.to_instr(len(args))
    yield InstrName.CALL.to_instr(len(args))
