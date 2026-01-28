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

import datetime
import struct
from enum import IntEnum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathorlib.utils import (
    get_address_b58_from_bytes,
    get_hash160,
    get_public_key_from_bytes_compressed,
    is_pubkey_compressed,
)
from hathorlib.exceptions import (
    EqualVerifyFailed,
    InvalidOpcodeError,
    InvalidStackData,
    MissingStackItems,
    OracleChecksigFailed,
    ScriptError,
    TimeLocked,
    VerifyFailed,
)
from hathorlib.scripts.execute import (
    Stack,
    UtxoScriptExtras,
    binary_to_int,
    decode_opn,
    get_data_value,
    get_script_op,
)
from hathorlib.scripts.script_context import ScriptContext


class Opcode(IntEnum):
    OP_0 = 0x50
    OP_1 = 0x51
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60
    OP_DUP = 0x76
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xAC
    OP_HASH160 = 0xA9
    OP_PUSHDATA1 = 0x4C
    OP_GREATERTHAN_TIMESTAMP = 0x6F
    OP_CHECKMULTISIG = 0xAE
    OP_CHECKDATASIG = 0xBA
    OP_DATA_STREQUAL = 0xC0
    OP_DATA_GREATERTHAN = 0xC1
    OP_FIND_P2PKH = 0xD0
    OP_DATA_MATCH_VALUE = 0xD1

    @classmethod
    def is_pushdata(cls, opcode: int) -> bool:
        """ Check if `opcode` represents an operation of pushing data on stack
        """
        if 1 <= opcode <= 75:
            # case: push [1,75] bytes on stack (op_pushdata)
            return True
        elif cls.OP_0 <= opcode <= cls.OP_16:
            # case: push integer on stack (op_integer)
            return True
        elif opcode == cls.OP_PUSHDATA1:
            # case: op_pushdata1
            return True
        # ...Any other case
        return False

    @classmethod
    def is_valid_opcode(cls, opcode: int) -> bool:
        """ Check if `opcode` is valid
            - check for pushdata first to validate unconventional opcodes for data
            - check for conventional opcode
        """
        if cls.is_pushdata(opcode):
            return True
        try:
            cls(opcode)
        except ValueError:
            return False
        else:
            return True


def op_pushdata(position: int, full_data: bytes, stack: Stack) -> int:
    """Pushes to stack when data is up to 75 bytes

    :param position: current position we're reading from full_data
    :type input_data: int

    :param full_data: input data + output script combined
    :type full_data: bytes

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises OutOfData: if data length to read is larger than what's available

    :return: new position to be read from full_data
    :rtype: int
    """

    length, new_pos = get_script_op(position, full_data, stack)
    assert length <= 75
    return new_pos


def op_pushdata1(position: int, full_data: bytes, stack: Stack) -> int:
    """Pushes data to stack; next byte contains number of bytes to be pushed

    :param position: current position we're reading from full_data
    :type input_data: int

    :param full_data: input data + output script combined
    :type full_data: bytes

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises OutOfData: if data length to read is larger than what's available

    :return: new position to be read from full_data
    :rtype: int
    """
    opcode, new_pos = get_script_op(position, full_data, stack)
    assert opcode == Opcode.OP_PUSHDATA1
    return new_pos


def op_dup(context: ScriptContext) -> None:
    """Duplicates item on top of stack

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(context.stack):
        raise MissingStackItems('OP_DUP: empty stack')
    context.stack.append(context.stack[-1])


def op_greaterthan_timestamp(context: ScriptContext) -> None:
    """Check whether transaction's timestamp is greater than the top of stack

    The top of stack must be a big-endian u32int.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(context.stack):
        raise MissingStackItems('OP_GREATERTHAN_TIMESTAMP: empty stack')
    buf = context.stack.pop()
    assert isinstance(buf, bytes)
    (timelock,) = struct.unpack('!I', buf)
    assert isinstance(context.extras, UtxoScriptExtras)
    if context.extras.tx.timestamp <= timelock:
        raise TimeLocked('The output is locked until {}'.format(
            datetime.datetime.fromtimestamp(timelock).strftime("%m/%d/%Y %I:%M:%S %p")))


def op_equalverify(context: ScriptContext) -> None:
    """Verifies top 2 elements from stack are equal

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there aren't 2 element on stack
    :raises EqualVerifyFailed: items don't match
    """
    if len(context.stack) < 2:
        raise MissingStackItems('OP_EQUALVERIFY: need 2 elements on stack, currently {}'.format(len(context.stack)))
    op_equal(context)
    is_equal = context.stack.pop()
    if not is_equal:
        raise EqualVerifyFailed('Failed to verify if elements are equal')


def op_equal(context: ScriptContext) -> None:
    """Verifies top 2 elements from stack are equal

    In case they are the same, we push 1 to the stack and push 0 if they are different

    :param stack: the stack used when evaluating the script
    :type stack: list[]
    """
    if len(context.stack) < 2:
        raise MissingStackItems('OP_EQUAL: need 2 elements on stack, currently {}'.format(len(context.stack)))
    elem1 = context.stack.pop()
    elem2 = context.stack.pop()
    assert isinstance(elem1, bytes)
    assert isinstance(elem2, bytes)
    if elem1 == elem2:
        context.stack.append(1)
    else:
        context.stack.append(0)
        context.logs.append('OP_EQUAL: failed. elements: {} {}'.format(elem1.hex(), elem2.hex()))


def op_checksig(context: ScriptContext) -> None:
    """Verifies public key and signature match. Expects public key to be on top of stack, followed
    by signature. If they match, put 1 on stack (meaning True); otherwise, push 0 (False)

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there aren't 2 element on stack
    :raises ScriptError: if pubkey on stack is not a compressed public key

    :return: if they don't match, return error message
    :rtype: string
    """
    if len(context.stack) < 2:
        raise MissingStackItems('OP_CHECKSIG: need 2 elements on stack, currently {}'.format(len(context.stack)))
    pubkey = context.stack.pop()
    signature = context.stack.pop()
    assert isinstance(pubkey, bytes)
    assert isinstance(signature, bytes)

    if not is_pubkey_compressed(pubkey):
        raise ScriptError('OP_CHECKSIG: pubkey is not a compressed public key')
    try:
        public_key = get_public_key_from_bytes_compressed(pubkey)
    except ValueError as e:
        # pubkey is not compressed public key
        raise ScriptError('OP_CHECKSIG: pubkey is not a public key') from e
    try:
        public_key.verify(signature, context.extras.tx.get_sighash_all_data(), ec.ECDSA(hashes.SHA256()))
        # valid, push true to stack
        context.stack.append(1)
    except InvalidSignature:
        # invalid, push false to stack
        context.stack.append(0)
        context.logs.append('OP_CHECKSIG: failed')


def op_hash160(context: ScriptContext) -> None:
    """Top stack item is hashed twice: first with SHA-256 and then with RIPEMD-160.
    Result is pushed back to stack.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(context.stack):
        raise MissingStackItems('OP_HASH160: empty stack')
    elem1 = context.stack.pop()
    assert isinstance(elem1, bytes)
    new_elem = get_hash160(elem1)
    context.stack.append(new_elem)


def op_checkdatasig(context: ScriptContext) -> None:
    """Verifies public key, signature and data match. Expects public key to be on top of stack, followed
    by signature and data. If they match, put data on stack; otherwise, fail.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises OracleChecksigFailed: invalid signature, given data and public key
    """
    if len(context.stack) < 3:
        raise MissingStackItems('OP_CHECKDATASIG: need 3 elements on stack, currently {}'.format(len(context.stack)))
    pubkey = context.stack.pop()
    signature = context.stack.pop()
    data = context.stack.pop()
    assert isinstance(pubkey, bytes)
    assert isinstance(signature, bytes)
    assert isinstance(data, bytes)

    if not is_pubkey_compressed(pubkey):
        raise ScriptError('OP_CHECKDATASIG: pubkey is not a compressed public key')
    try:
        public_key = get_public_key_from_bytes_compressed(pubkey)
    except ValueError as e:
        # pubkey is not compressed public key
        raise ScriptError('OP_CHECKDATASIG: pubkey is not a public key') from e
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        # valid, push true to stack
        context.stack.append(data)
    except InvalidSignature as e:
        raise OracleChecksigFailed from e


def op_data_strequal(context: ScriptContext) -> None:
    """Equivalent to an OP_GET_DATA_STR followed by an OP_EQUALVERIFY.

    Consumes three parameters from stack: <data> <k> <value>. Gets the kth value
    from <data> as a string and verifies it's equal to <value>. If so, puts <data>
    back on the stack.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(context.stack) < 3:
        raise MissingStackItems('OP_DATA_STREQUAL: need 3 elements on stack, currently {}'.format(len(context.stack)))
    value = context.stack.pop()
    data_k = context.stack.pop()
    data = context.stack.pop()
    assert isinstance(value, bytes)
    assert isinstance(data, bytes)

    if not isinstance(data_k, int):
        raise VerifyFailed('OP_DATA_STREQUAL: value on stack should be an integer ({!r})'.format(data_k))

    data_value = get_data_value(data_k, data)
    if data_value != value:
        raise VerifyFailed('OP_DATA_STREQUAL: {} x {}'.format(data_value.decode('utf-8'), value.decode('utf-8')))

    context.stack.append(data)


def op_data_greaterthan(context: ScriptContext) -> None:
    """Equivalent to an OP_GET_DATA_INT followed by an OP_GREATERTHAN.

    Consumes three parameters from stack: <data> <k> <n>. Gets the kth value
    from <data> as an integer and verifies it's greater than <n>.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(context.stack) < 3:
        raise MissingStackItems(f'OP_DATA_GREATERTHAN: need 3 elements on stack, currently {len(context.stack)}')
    value = context.stack.pop()
    data_k = context.stack.pop()
    data = context.stack.pop()
    assert isinstance(value, bytes)
    assert isinstance(data, bytes)

    if not isinstance(data_k, int):
        raise VerifyFailed('OP_DATA_STREQUAL: value on stack should be an integer ({!r})'.format(data_k))

    data_value = get_data_value(data_k, data)
    try:
        data_int = binary_to_int(data_value)
        value_int = binary_to_int(value)
    except (ValueError, struct.error) as e:
        raise VerifyFailed from e

    if data_int <= value_int:
        raise VerifyFailed('op_data_greaterthan: {} x {}'.format(data_int, value_int))

    context.stack.append(data)


def op_data_match_interval(stack: Stack) -> None:
    """Equivalent to an OP_GET_DATA_INT followed by an OP_MATCH_INTERVAL.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(stack) < 1:
        raise MissingStackItems('OP_DATA_MATCH_INTERVAL: stack is empty')

    data_n_items = stack.pop()
    assert isinstance(data_n_items, bytes)
    # TODO test this can be transformed to integer
    n_items = data_n_items[0]

    # number of items in stack that will be used
    will_use = 2 * n_items + 3  # n data_points, n + 1 pubkeys, k and data
    if len(stack) < will_use:
        raise MissingStackItems('OP_DATA_MATCH_INTERVAL: need {} elements on stack, currently {}'.format(
            will_use, len(stack)))

    items = []
    try:
        for _ in range(n_items):
            pubkey = stack.pop()
            buf = stack.pop()
            assert isinstance(pubkey, (str, bytes))
            assert isinstance(buf, bytes)
            value = binary_to_int(buf)
            items.append((value, pubkey))
        # one pubkey is left on stack
        last_pubkey = stack.pop()
        # next two items are data index and data
        data_k = stack.pop()
        data = stack.pop()
        assert isinstance(data_k, int)
        assert isinstance(data, bytes)
        data_value = get_data_value(data_k, data)
        data_int = binary_to_int(data_value)
    except (ValueError, struct.error) as e:
        raise VerifyFailed from e

    for (value_int, pubkey) in items:
        if data_int > value_int:
            stack.append(pubkey)
            return
    # if none of the values match, last pubkey on stack is winner
    stack.append(last_pubkey)


def op_data_match_value(context: ScriptContext) -> None:
    """Equivalent to an OP_GET_DATA_STR followed by an OP_MATCH_VALUE.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(context.stack) < 1:
        raise MissingStackItems('OP_DATA_MATCH_VALUE: empty stack')

    data_n_items = context.stack.pop()
    assert isinstance(data_n_items, bytes)
    # TODO test this can be transformed to integer
    n_items = data_n_items[0]

    # number of items in stack that will be used
    will_use = 2 * n_items + 3  # n data_points, n + 1 keys, k and data
    if len(context.stack) < will_use:
        raise MissingStackItems('OP_DATA_MATCH_VALUE: need {} elements on stack, currently {}'.format(
            will_use, len(context.stack)))

    items = {}
    try:
        for _ in range(n_items):
            pubkey = context.stack.pop()
            buf = context.stack.pop()
            assert isinstance(pubkey, (str, bytes))
            assert isinstance(buf, bytes)
            value = binary_to_int(buf)
            items[value] = pubkey
    except (ValueError, struct.error) as e:
        raise VerifyFailed from e

    # one pubkey is left on stack
    last_pubkey = context.stack.pop()
    # next two items are data index and data
    data_k = context.stack.pop()
    data = context.stack.pop()
    assert isinstance(data_k, int)
    assert isinstance(data, bytes)
    data_value = get_data_value(data_k, data)
    data_int = binary_to_int(data_value)
    winner_pubkey = items.get(data_int, last_pubkey)
    assert isinstance(winner_pubkey, (str, bytes))
    context.stack.append(winner_pubkey)


def op_find_p2pkh(context: ScriptContext) -> None:
    """Checks whether the current transaction has an output with a P2PKH script with
    the given public key hash and the same amount as the input.

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :param tx: Transaction to be added
    :type tx: :py:class:`hathor.transaction.GenericVertex`

    :param contract_value: amount available on the nano contract (on the original output)
    :type contract_type: int

    :raises MissingStackItems: if stack is empty
    :raises VerifyFailed: verification failed
    """
    if not len(context.stack):
        raise MissingStackItems('OP_FIND_P2PKH: empty stack')

    from hathorlib.scripts import P2PKH
    assert isinstance(context.extras, UtxoScriptExtras)
    spent_tx = context.extras.spent_tx
    txin = context.extras.txin
    tx = context.extras.tx
    contract_value = spent_tx.outputs[txin.index].value

    address = context.stack.pop()
    address_b58 = get_address_b58_from_bytes(address)
    for output in tx.outputs:
        p2pkh_out = P2PKH.parse_script(output.script)
        if p2pkh_out:
            if p2pkh_out.address == address_b58 and output.value == contract_value:
                context.stack.append(1)
                return
    # didn't find any match
    raise VerifyFailed


def op_checkmultisig(context: ScriptContext) -> None:
    """Checks if it has the minimum signatures required and if all of them are valid

    :param stack: the stack used when evaluating the script
    :type stack: list[]

    :raises MissingStackItems: if stack is empty or it has less signatures than the minimum required
    :raises VerifyFailed: verification failed
    """
    settings = context.extras.settings
    assert settings is not None, 'settings is required to run scripts'

    if not len(context.stack):
        raise MissingStackItems('OP_CHECKMULTISIG: empty stack')

    # Pop the quantity of pubkeys
    pubkey_count = context.stack.pop()

    if not isinstance(pubkey_count, int):
        raise InvalidStackData('OP_CHECKMULTISIG: pubkey count should be an integer')

    if pubkey_count > settings.MAX_MULTISIG_PUBKEYS:
        raise InvalidStackData('OP_CHECKMULTISIG: pubkey count ({}) exceeded the limit ({})'.format(
                pubkey_count,
                settings.MAX_MULTISIG_PUBKEYS,
                )
            )

    if len(context.stack) < pubkey_count:
        raise MissingStackItems('OP_CHECKMULTISIG: not enough public keys on the stack')

    # Get all pubkeys
    pubkeys = []
    for _ in range(pubkey_count):
        pubkey_bytes = context.stack.pop()
        pubkeys.append(pubkey_bytes)

    if not len(context.stack):
        raise MissingStackItems('OP_CHECKMULTISIG: less elements than should on the stack')

    # Pop the quantity of signatures required
    signatures_count = context.stack.pop()

    if not isinstance(signatures_count, int):
        raise InvalidStackData('OP_CHECKMULTISIG: signatures count should be an integer')

    if signatures_count > settings.MAX_MULTISIG_SIGNATURES:
        raise InvalidStackData('OP_CHECKMULTISIG: signature count ({}) exceeded the limit ({})'.format(
                signatures_count,
                settings.MAX_MULTISIG_SIGNATURES,
                )
            )

    # Error if we don't have the minimum quantity of signatures
    if len(context.stack) < signatures_count:
        raise MissingStackItems('OP_CHECKMULTISIG: not enough signatures on the stack')

    # Get all signatures
    signatures = []
    for _ in range(signatures_count):
        signature_bytes = context.stack.pop()
        signatures.append(signature_bytes)

    # For each signature we check if it's valid with one of the public keys
    # Signatures must be in order (same as the public keys in the multi sig wallet)
    pubkey_index = 0
    for signature in signatures:
        while pubkey_index < len(pubkeys):
            pubkey = pubkeys[pubkey_index]
            new_stack = [signature, pubkey]
            op_checksig(ScriptContext(stack=new_stack, logs=context.logs, extras=context.extras))
            result = new_stack.pop()
            pubkey_index += 1
            if result == 1:
                break
        else:
            # finished all pubkeys and did not verify all signatures
            context.stack.append(0)
            return

    # If all signatures are valids we push 1
    context.stack.append(1)


def op_integer(opcode: int, stack: Stack) -> None:
    """ Appends an integer to the stack
        We get the opcode comparing to all integers opcodes

        Example to append integer 4:
        opcode will be equal to OP_4 (0x54)
        Then we append the integer OP_4 - OP_0 = 4

        :param opcode: the opcode to append to the stack
        :type opcode: bytes

        :param stack: the stack used when evaluating the script
        :type stack: list[]
    """
    try:
        stack.append(decode_opn(opcode))
    except InvalidOpcodeError as e:
        raise ScriptError(e) from e


def execute_op_code(opcode: Opcode, context: ScriptContext) -> None:
    """
    Execute a function opcode.

    Args:
        opcode: the opcode to be executed.
        context: the script context to be manipulated.
    """
    context.logs.append(f'Executing function opcode {opcode.name} ({hex(opcode.value)})')
    match opcode:
        case Opcode.OP_DUP:
            op_dup(context)
        case Opcode.OP_EQUAL:
            op_equal(context)
        case Opcode.OP_EQUALVERIFY:
            op_equalverify(context)
        case Opcode.OP_CHECKSIG:
            op_checksig(context)
        case Opcode.OP_HASH160:
            op_hash160(context)
        case Opcode.OP_GREATERTHAN_TIMESTAMP:
            op_greaterthan_timestamp(context)
        case Opcode.OP_CHECKMULTISIG:
            op_checkmultisig(context)
        case Opcode.OP_DATA_STREQUAL:
            op_data_strequal(context)
        case Opcode.OP_DATA_GREATERTHAN:
            op_data_greaterthan(context)
        case Opcode.OP_DATA_MATCH_VALUE:
            op_data_match_value(context)
        case Opcode.OP_CHECKDATASIG:
            op_checkdatasig(context)
        case Opcode.OP_FIND_P2PKH:
            op_find_p2pkh(context)
        case _:
            raise ScriptError(f'unknown opcode: {opcode}')
