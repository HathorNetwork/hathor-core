#  Copyright 2023 Hathor Labs
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

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple, Optional, Union

from hathor.transaction import BaseTransaction, Transaction, TxInput
from hathor.transaction.exceptions import DataIndexError, FinalStackInvalid, InvalidScriptError, OutOfData

if TYPE_CHECKING:
    from hathor.transaction.scripts.opcode import OpcodesVersion


@dataclass(slots=True, frozen=True, kw_only=True)
class ScriptExtras:
    tx: Transaction
    version: OpcodesVersion


@dataclass(slots=True, frozen=True, kw_only=True)
class UtxoScriptExtras(ScriptExtras):
    txin: TxInput
    spent_tx: BaseTransaction


# XXX: Because the Stack is a heterogeneous list of bytes and int, and some OPs only work for when the stack has some
#      or the other type, there are many places that require an assert to prevent the wrong type from being used,
#      alternatives include: 1. only using `list[bytes]` and operations that work on `int` to build them from `bytes`,
#      2. using `bytearray` instead of `list[...]` and using type codes on the stack or at least value sizes on the
#      stack and OPs should use the extra info accordingly 3. using some "in stack error" at least custom exceptions
#      for signaling that an OP was applied on a wrongly typed stack.
Stack = list[Union[bytes, int, str]]


class OpcodePosition(NamedTuple):
    opcode: int
    position: int


def execute_eval(data: bytes, log: list[str], extras: ScriptExtras) -> None:
    """ Execute eval from data executing opcode methods

        :param data: data to be evaluated that contains data and opcodes
        :type data: bytes

        :param log: list of log messages
        :type log: list[str]

        :param extras: namedtuple with extra fields
        :type extras: :py:class:`hathor.transaction.scripts.ScriptExtras`

        :raises ScriptError: case opcode is not found
        :raises FinalStackInvalid: case the evaluation fails
    """
    from hathor.transaction.scripts.opcode import Opcode, execute_op_code
    from hathor.transaction.scripts.script_context import ScriptContext
    stack: Stack = []
    context = ScriptContext(stack=stack, logs=log, extras=extras)
    data_len = len(data)
    pos = 0
    while pos < data_len:
        opcode, pos = get_script_op(pos, data, stack)
        if Opcode.is_pushdata(opcode):
            continue

        # this is an opcode manipulating the stack
        execute_op_code(Opcode(opcode), context, extras.version)

    evaluate_final_stack(stack, log)


def evaluate_final_stack(stack: Stack, log: list[str]) -> None:
    """ Checks the final state of the stack.
        It's valid if only has 1 value on stack and that value is 1 (true)
    """
    if len(stack) == 0:
        log.append('Empty Stack left')
        raise FinalStackInvalid('\n'.join(log))
    if len(stack) > 1:
        log.append('Stack left with more than one value')
        raise FinalStackInvalid('\n'.join(log))
    # check if value left on stack is 1 (true)
    if stack.pop() != 1:
        # stack left with non-True value
        log.append('Stack left with False value')
        raise FinalStackInvalid('\n'.join(log))


def script_eval(tx: Transaction, txin: TxInput, spent_tx: BaseTransaction, version: OpcodesVersion) -> None:
    """Evaluates the output script and input data according to
    a very limited subset of Bitcoin's scripting language.

    :param tx: the transaction being validated, the 'owner' of the input data
    :type tx: :py:class:`hathor.transaction.Transaction`

    :param txin: transaction input being evaluated
    :type txin: :py:class:`hathor.transaction.TxInput`

    :param spent_tx: the transaction referenced by the input
    :type spent_tx: :py:class:`hathor.transaction.BaseTransaction`

    :raises ScriptError: if script verification fails
    """
    # VULN-002 / CONS-007: Use resolve_spent_output for shielded-aware lookup
    try:
        resolved = spent_tx.resolve_spent_output(txin.index)
    except IndexError:
        raise InvalidScriptError(f'input index {txin.index} out of range')
    output_script = resolved.script
    raw_script_eval(
        input_data=txin.data,
        output_script=output_script,
        extras=UtxoScriptExtras(tx=tx, txin=txin, spent_tx=spent_tx, version=version),
    )


def raw_script_eval(*, input_data: bytes, output_script: bytes, extras: ScriptExtras) -> None:
    log: list[str] = []

    from hathor.transaction.scripts import MultiSig
    if MultiSig.re_match.search(output_script):
        # For MultiSig there are 2 executions:
        # First we need to evaluate that redeem_script matches redeem_script_hash
        # we can't use input_data + output_script because it will end with an invalid stack
        # i.e. the signatures will still be on the stack after ouput_script is executed
        redeem_script_pos = MultiSig.get_multisig_redeem_script_pos(input_data)
        full_data = input_data[redeem_script_pos:] + output_script
        execute_eval(full_data, log, extras)

        # Second, we need to validate that the signatures on the input_data solves the redeem_script
        # we pop and append the redeem_script to the input_data and execute it
        multisig_data = MultiSig.get_multisig_data(input_data)
        execute_eval(multisig_data, log, extras)
    else:
        # merge input_data and output_script
        full_data = input_data + output_script
        execute_eval(full_data, log, extras)


def decode_opn(opcode: int) -> int:
    """ Decode integer opcode (OP_N) to its integer value

        :param opcode: the opcode to convert
        :type opcode: bytes

        :raises InvalidScriptError: case opcode is not a valid OP_N

        :return: int value for opcode param
        :rtype: int
    """
    from hathor.transaction.scripts import Opcode
    int_val = opcode - Opcode.OP_0
    if not (0 <= int_val <= 16):
        raise InvalidScriptError('unknown opcode {}'.format(opcode))
    return int_val


def get_script_op(pos: int, data: bytes, stack: Optional[Stack] = None) -> OpcodePosition:
    """ Interpret opcode at `pos` and return the opcode and the position of the next opcode
        if opcode is a pushdata, push extracted data to stack if there is a stack

        :param pos: position of opcode to read
        :type pos: int

        :param data: script to be evaluated that contains data and opcodes
        :type data: bytes

        :param stack: stack to put any extracted data or None if not interested on the extracted data
        :type stack: Union[Stack, None]

        :raises OutOfData: when trying to read out of script
        :raises InvalidScriptError: when opcode in `pos` is invalid

        :return: extracted opcode at `pos` and position of next opcode on `data`
        :rtype: OpcodePosition
    """
    opcode = get_data_single_byte(pos, data)

    # validate opcode
    from hathor.transaction.scripts import Opcode
    if not Opcode.is_valid_opcode(opcode):
        raise InvalidScriptError('Invalid Opcode ({}) at position {} in {!r}'.format(opcode, pos, data))

    to_append: Union[bytes, int, str]
    if 1 <= opcode <= 75:
        # pushdata: push up to 75 bytes on stack
        pos += 1
        to_append = get_data_bytes(pos, opcode, data)
        pos += opcode
        if stack is not None:
            stack.append(to_append)
    elif opcode == Opcode.OP_PUSHDATA1:
        # pushdata1: push up to 255 bytes on stack
        pos += 1
        length = get_data_single_byte(pos, data)
        pos += 1
        to_append = get_data_bytes(pos, length, data)
        pos += length
        if stack is not None:
            stack.append(to_append)
    elif Opcode.OP_0 <= opcode <= Opcode.OP_16:
        # OP_N: push and  integer (0 to 16) to stack
        # OP_N in [OP_0, OP_16]
        to_append = decode_opn(opcode)
        pos += 1
        if stack is not None:
            stack.append(to_append)
    else:
        # if opcode is a function and not a pushdata, move pos to next byte (next opcode)
        pos += 1

    return OpcodePosition(opcode=opcode, position=pos)


def get_data_value(k: int, data: bytes) -> bytes:
    """Extracts the kth value from data.

    data should be in the format value0:value1:value2:...:valueN. This last representation
    is merely for understanding the logic. In practice, data will be a sequence of bytes,
    with each value preceded by the length of such value.

    # TODO allow values larger than 255 bytes (some logic similar to OP_PUSHDATA1?)

    :param k: index of item to retrieve
    :type k: int

    :param data: data to get value from
    :type data: bytes

    :raises OutOfData: if data length to read is larger than what's available
    :raises DataIndexError: index requested from data is not available
    """
    data_len = len(data)
    position = 0
    iteration = 0
    while position < data_len:
        length = data[position]
        if length == 0:
            # TODO throw error
            pass
        position += 1
        if (position + length) > len(data):
            raise OutOfData('trying to read {} bytes starting at {}, available {}'.format(length, position, len(data)))
        value = data[position:position + length]
        if iteration == k:
            return value
        iteration += 1
        position += length
    raise DataIndexError


def binary_to_int(binary: bytes) -> int:
    """Receives a binary and transforms it to an integer

    :param binary: value to convert
    :type binary: bytes
    """
    if len(binary) == 1:
        _format = '!B'
    elif len(binary) == 2:
        _format = '!H'
    elif len(binary) == 4:
        _format = '!I'
    elif len(binary) == 8:
        _format = '!Q'
    else:
        raise struct.error

    (value,) = struct.unpack(_format, binary)
    return value


def get_data_bytes(position: int, length: int, data: bytes) -> bytes:
    """ Extract `length` bytes from `data` starting at `position`

        :param position: start position of bytes string to extract
        :type position: int

        :param length: len of bytes str to extract
        :type length: int

        :param data: script containing data to extract
        :type data: bytes

        :raises OutOfData: when trying to read out of script

        :return: bytes string of extracted data
        :rtype: bytes
    """
    if not (0 < length <= len(data)):
        raise OutOfData("length ({}) should be from 0 up to data length".format(length))
    if not (0 < position < len(data)):
        raise OutOfData("position should be inside data")
    if (position+length) > len(data):
        raise OutOfData('trying to read {} bytes starting at {}, available {}'.format(length, position, len(data)))
    return data[position:position+length]


def get_data_single_byte(position: int, data: bytes) -> int:
    """ Extract 1 byte from `data` at `position`

        :param position: position of byte to extract
        :type position: int

        :param data: script containing data to extract
        :type data: bytes

        :raises OutOfData: when trying to read out of script

        :return: extracted byte
        :rtype: int
    """
    if not (0 <= position < len(data)):
        raise OutOfData("trying to read a byte at {} outside of data, available {}".format(position, len(data)))
    return data[position]
