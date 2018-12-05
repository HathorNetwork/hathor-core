from enum import IntEnum
from collections import namedtuple
import struct
import hashlib
import re
import datetime

from twisted.logger import Logger

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from hathor.crypto.util import get_hash160, get_public_key_from_bytes_compressed, get_address_b58_from_bytes, \
                                get_address_b58_from_public_key_bytes_compressed, get_address_b58_from_public_key_hash
from hathor.transaction.exceptions import ScriptError, OutOfData, MissingStackItems, \
                                          EqualVerifyFailed, FinalStackInvalid, TimeLocked, \
                                          OracleChecksigFailed, DataIndexError, VerifyFailed


ScriptExtras = namedtuple('ScriptExtras', 'tx txin spent_tx')


def re_compile(pattern):
    """ Transform a given script pattern into a regular expression.

    The script pattern is like a regular expression, but you may include two
    special symbols: (i) OP_DUP, OP_HASH160, and all other opcodes, and
    (ii) DATA_<length>.

    Example:
    >>> re_compile(
    ...     '^(?:DATA_4 OP_GREATERTHAN_TIMESTAMP)? '
    ...     'OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKSIG$'
    ... )

    :return: A compiled regular expression matcher
    :rtype: :py:class:`re.Pattern`
    """
    def _to_byte_pattern(m):
        x = m.group().decode('ascii').strip()
        if x.startswith('OP_'):
            return bytes([Opcode[x]])
        elif x.startswith('DATA_'):
            length = int(m.group()[5:])
            return _re_pushdata(length)
        else:
            raise ValueError('Invalid opcode: {}'.format(x))

    p = pattern.encode('ascii')
    p = re.sub(rb'\s*([A-Z0-9_]+)\s*', _to_byte_pattern, p)
    return re.compile(p, re.DOTALL)


def _re_pushdata(length):
    """ Create a regular expression that matches a data block with a given length.

    :return: A non-compiled regular expression
    :rtype: bytes
    """
    p1 = [
        bytes([Opcode.OP_PUSHDATA1]),
        b'.{',
        str(length + 1).encode('ascii'),
        b'}'
    ]

    if length >= 75:
        ret = p1
    else:
        p2 = [
            b'[\0-\75].{',
            str(length).encode('ascii'),
            b'}'
        ]
        ret = [
            b'(?:(?:',
            b''.join(p1),
            b')|(?:',
            b''.join(p2),
            b'))',
        ]

    return b''.join(ret)


class Opcode(IntEnum):
    OP_DUP = 0x76
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xAC
    OP_HASH160 = 0xA9
    OP_PUSHDATA1 = 0x4C
    OP_GREATERTHAN_TIMESTAMP = 0x6F


class HathorScript:
    """This class is supposes to being a helper creating the scripts. It abstracts
    some of the corner cases when building the script.

    For eg, when pushing data to the stack, we may or may not have to use OP_PUSHDATA.
    This is the sequence we have to add to the script:
    - len(data) <= 75: [len(data) data]
    - len(data) > 75: [OP_PUSHDATA1 len(data) data]

    pushData abstracts this differences and presents an unique interface.
    """
    log = Logger()

    def __init__(self):
        self.data = b''

    def addOpcode(self, opcode):
        self.data += bytes([opcode])

    def pushData(self, data):
        if len(data) <= 75:
            self.data += (bytes([len(data)]) + data)
        else:
            self.data += (bytes([Opcode.OP_PUSHDATA1]) + bytes([len(data)]) + data)


class P2PKH:
    re_match = re_compile(
        '^(?:(DATA_4) OP_GREATERTHAN_TIMESTAMP)? '
        'OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKSIG$'
    )

    def __init__(self, address, timelock=None):
        """This class represents the pay to public hash key script. It enables the person
        who has the corresponding private key of the address to spend the tokens.

        This script validates the signature and public key on the corresponding input
        data. The public key is first checked against the script address and then the
        signature is verified, which means the sender owns the corresponding private key.

        Output script and the corresponding input data are usually represented like:
        input data: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        output script: <sig> <pubKey>

        :param address: address to send tokens
        :type address: string(base58)

        :param timelock: timestamp until when it's locked
        :type timelock: int
        """
        self.address = address
        self.timelock = timelock

    def to_human_readable(self):
        ret = {}
        ret['type'] = 'P2PKH'
        ret['address'] = self.address
        ret['timelock'] = self.timelock
        return ret

    @classmethod
    def create_output_script(cls, address, timelock=None):
        """
        :param address: address to send tokens
        :type address: bytes

        :param timelock: timestamp until when the output is locked
        :type timelock: bytes

        :rtype: bytes
        """
        assert len(address) == 25
        public_key_hash = address[1:-4]
        s = HathorScript()
        if timelock:
            s.pushData(timelock)
            s.addOpcode(Opcode.OP_GREATERTHAN_TIMESTAMP)
        s.addOpcode(Opcode.OP_DUP)
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(public_key_hash)
        s.addOpcode(Opcode.OP_EQUALVERIFY)
        s.addOpcode(Opcode.OP_CHECKSIG)
        return s.data

    @classmethod
    def create_input_data(cls, public_key_bytes, signature):
        """
        :param private_key: key corresponding to the address we want to spend tokens from
        :type private_key: :py:class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`

        :rtype: bytes
        """
        s = HathorScript()
        s.pushData(signature)
        s.pushData(public_key_bytes)
        return s.data

    @classmethod
    def verify_script(cls, script):
        """Checks if the given script is of type p2pkh. If it is, returns the P2PKH object.
        Otherwise, returns None.

        TODO come up with better method name [yan]
        TODO this is a very naive approach

        :param script: script to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.P2PKH` or None
        """
        match = cls.re_match.search(script)
        if match:
            groups = match.groups()
            timelock = None
            pushdata_timelock = groups[0]
            if pushdata_timelock:
                timelock_bytes = pushdata_timelock[1:]
                timelock = struct.unpack('!I', timelock_bytes)[0]
            pushdata_address = groups[1]
            if pushdata_address[0] > 75:
                public_key_hash = pushdata_address[2:]
            else:
                public_key_hash = pushdata_address[1:]
            address_b58 = get_address_b58_from_public_key_hash(public_key_hash)
            return cls(address_b58, timelock)
        return None

    @classmethod
    def verify_input(cls, input_data):
        """Checks if the given input is of type p2pkh. If it is, returns the P2PKH object.
        Otherwise, returns None.

        TODO come up with better method name [yan]
        TODO this is a very naive approach
        TODO this considers only PUSHDATA1

        :param script: input data to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.P2PKH` or None
        """
        opcode = input_data[0]
        if opcode <= 75:
            siglen = opcode
            pos = 1
        else:
            siglen = input_data[1]
            pos = 2
        pos = siglen + pos
        opcode = input_data[pos]
        if opcode <= 75:
            pass
        else:
            pos += 1
        public_key = input_data[pos+1:]
        address = get_address_b58_from_public_key_bytes_compressed(public_key)
        return cls(address)


def script_eval(tx, txin, spent_tx):
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
    input_data = txin.data
    output_script = spent_tx.outputs[txin.index].script

    stack = []
    # merge input_data and output_script
    full_data = input_data + output_script
    data_len = len(full_data)
    pos = 0
    log = []
    extras = ScriptExtras(tx=tx, txin=txin, spent_tx=spent_tx)
    while pos < data_len:
        opcode = full_data[pos]
        if (opcode >= 1 and opcode <= 75):
            pos = op_pushdata(pos, full_data, stack)
            continue
        elif opcode == Opcode.OP_PUSHDATA1:
            pos = op_pushdata1(pos, full_data, stack)
            continue

        # self.log.debug('!! pos={} opcode={} {}'.format(pos, opcode, Opcode(opcode)))

        # this is an opcode manipulating the stack
        fn = MAP_OPCODE_TO_FN.get(opcode, None)
        if fn is None:
            # throw error
            raise ScriptError('unknown opcode')

        fn(stack, log, extras)
        pos += 1

    if len(stack) > 0:
        if stack.pop() != 1:
            # stack left with non zero value
            raise FinalStackInvalid('\n'.join(log))


def op_pushdata(position, full_data, stack):
    """Pushes to stack when data is up to 75 bytes

    :param position: current position we're reading from full_data
    :type input_data: int

    :param full_data: input data + output script combined
    :type full_data: bytes

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises OutOfData: if data length to read is larger than what's available

    :return: new position to be read from full_data
    :rtype: int
    """
    length = full_data[position]
    assert length <= 75
    position += 1
    if (position + length) > len(full_data):
        raise OutOfData('trying to read {} bytes starting at {}, available {}'
                        .format(length, position, len(full_data)))
    stack.append(full_data[position:position+length])
    return position + length


def op_pushdata1(position, full_data, stack):
    """Pushes data to stack; next byte contains number of bytes to be pushed

    :param position: current position we're reading from full_data
    :type input_data: int

    :param full_data: input data + output script combined
    :type full_data: bytes

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises OutOfData: if data length to read is larger than what's available

    :return: new position to be read from full_data
    :rtype: int
    """
    data_len = len(full_data)
    # next position is data length to push
    position += 1
    if position >= data_len:
        raise OutOfData('trying to read byte {}, available {}'.format(position, data_len))
    length = full_data[position]
    if (position + length) >= data_len:
        raise OutOfData('trying to read {} bytes starting at {}, available {}'.format(length, position, data_len))
    position += 1
    stack.append(full_data[position:position+length])
    return position + length


def op_dup(stack, log, extras):
    """Duplicates item on top of stack

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(stack):
        raise MissingStackItems('OP_DUP: empty stack')
    stack.append(stack[-1])


def op_greaterthan_timestamp(stack, log, extras):
    """Check whether transaction's timestamp is greater than the top of stack

    The top of stack must be a big-endian u32int.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(stack):
        raise MissingStackItems('OP_GREATERTHAN_TIMESTAMP: empty stack')
    buf = stack.pop()
    (timelock,) = struct.unpack('!I', buf)
    if extras.tx.timestamp <= timelock:
        raise TimeLocked(
            'The output is locked until {}'.format(
                datetime.datetime.fromtimestamp(timelock).strftime("%m/%d/%Y %I:%M:%S %p")
            )
        )


def op_equalverify(stack, log, extras):
    """Verifies top 2 elements from stack are equal

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 2 element on stack
    :raises EqualVerifyFailed: items don't match
    """
    if len(stack) < 2:
        raise MissingStackItems('OP_EQUALVERIFY: need 2 elements on stack, currently {}')
    elem1 = stack.pop()
    elem2 = stack.pop()
    if elem1 != elem2:
        raise EqualVerifyFailed('elements: {} {}'.format(elem1.hex(), elem2.hex()))


def op_checksig(stack, log, extras):
    """Verifies public key and signature match. Expects public key to be on top of stack, followed
    by signature. If they match, put 1 on stack (meaning True); otherwise, push 0 (False)

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 2 element on stack

    :return: if they don't match, return error message
    :rtype: string
    """
    if len(stack) < 2:
        raise MissingStackItems('OP_CHECKSIG: need 2 elements on stack, currently {}'.format(len(stack)))
    pubkey = stack.pop()
    signature = stack.pop()
    public_key = get_public_key_from_bytes_compressed(pubkey)
    data_to_sign = extras.tx.get_sighash_all()
    hashed_data = hashlib.sha256(data_to_sign).digest()
    try:
        public_key.verify(signature, hashed_data, ec.ECDSA(hashes.SHA256()))
        # valid, push true to stack
        stack.append(1)
    except InvalidSignature:
        # invalid, push false to stack
        stack.append(0)
        log.append('OP_CHECKSIG: failed')


def op_hash160(stack, log, extras):
    """Top stack item is hashed twice: first with SHA-256 and then with RIPEMD-160.
    Result is pushed back to stack.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(stack):
        raise MissingStackItems('OP_HASH160: empty stack')
    elem1 = stack.pop()
    new_elem = get_hash160(elem1)
    stack.append(new_elem)


def op_checkdatasig(stack, log, extras):
    """Verifies public key, signature and data match. Expects public key to be on top of stack, followed
    by signature and data. If they match, put data on stack; otherwise, fail.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises OracleChecksigFailed: invalid signature, given data and public key
    """
    if len(stack) < 3:
        raise MissingStackItems('OP_CHECKDATASIG: need 3 elements on stack, currently {}'.format(len(stack)))
    pubkey = stack.pop()
    signature = stack.pop()
    data = stack.pop()
    public_key = get_public_key_from_bytes_compressed(pubkey)
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        # valid, push true to stack
        stack.append(data)
    except InvalidSignature as e:
        raise OracleChecksigFailed from e


def get_data_value(k, data):
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
            raise OutOfData('trying to read {} bytes starting at {}, available {}'
                            .format(length, position, len(data)))
        value = data[position:position+length]
        if iteration == k:
            return value
        iteration += 1
        position += length
    raise DataIndexError


def binary_to_int(binary):
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
        _format == '!L'
    else:
        raise struct.error

    (value,) = struct.unpack(_format, binary)
    return value


def op_data_strequal(stack, log, extras):
    """Equivalent to an OP_GET_DATA_STR followed by an OP_EQUALVERIFY.

    Consumes three parameters from stack: <data> <k> <value>. Gets the kth value
    from <data> as a string and verifies it's equal to <value>. If so, puts <data>
    back on the stack.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(stack) < 3:
        raise MissingStackItems('OP_DATA_STREQUAL: need 3 elements on stack, currently {}'.format(len(stack)))
    value = stack.pop()
    data_k = stack.pop()
    data_k_int = data_k[0]      # data_k is a 1-byte unsigned int
    data = stack.pop()

    data_value = get_data_value(data_k_int, data)
    if data_value != value:
        raise VerifyFailed

    stack.append(data)


def op_data_greaterthan(stack, log, extras):
    """Equivalent to an OP_GET_DATA_INT followed by an OP_GREATERTHAN.

    Consumes three parameters from stack: <data> <k> <n>. Gets the kth value
    from <data> as an integer and verifies it's greater than <n>.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(stack) < 3:
        raise MissingStackItems('OP_DATA_GREATERTHAN: need 3 elements on stack, currently {}'.format(len(stack)))
    value = stack.pop()
    data_k = stack.pop()
    data_k_int = data_k[0]      # data_k is a 1-byte unsigned int
    data = stack.pop()

    data_value = get_data_value(data_k_int, data)
    try:
        data_int = binary_to_int(data_value)
        value_int = binary_to_int(value)
    except (ValueError, struct.error) as e:
        raise VerifyFailed from e

    if data_int <= value_int:
        raise VerifyFailed

    stack.append(data)


def op_data_match_interval(stack, log, extras):
    """Equivalent to an OP_GET_DATA_INT followed by an OP_MATCH_INTERVAL.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(stack) < 1:
        raise MissingStackItems('OP_DATA_MATCH_INTERVAL: stack is empty')

    n_items = stack.pop()[0]
    # number of items in stack that will be used
    will_use = 2 * n_items + 3      # n data_points, n + 1 pubkeys, k and data
    if len(stack) < will_use:
        raise MissingStackItems('OP_DATA_MATCH_INTERVAL: need {} elements on stack, currently {}'
                                .format(will_use, len(stack)))

    items = []
    try:
        for _ in range(n_items):
            pubkey = stack.pop()
            buf = stack.pop()
            value = binary_to_int(buf)
            items.append((value, pubkey))
        # one pubkey is left on stack
        last_pubkey = stack.pop()
        # next two items are data index and data
        data_k = stack.pop()
        data_k_int = data_k[0]      # data_k is a 1-byte unsigned int
        data = stack.pop()
        data_value = get_data_value(data_k_int, data)
        data_int = binary_to_int(data_value)
    except (ValueError, struct.error) as e:
        raise VerifyFailed from e

    for (value_int, pubkey) in items:
        if data_int > value_int:
            stack.append(pubkey)
            return
    # if none of the values match, last pubkey on stack is winner
    stack.append(last_pubkey)


def op_data_match_value(stack, log, extras):
    """Equivalent to an OP_GET_DATA_STR followed by an OP_MATCH_VALUE.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(stack) < 1:
        raise MissingStackItems('OP_DATA_MATCH_VALUE: empty stack')
    n_items = stack.pop()[0]

    # number of items in stack that will be used
    will_use = 2 * n_items + 3      # n data_points, n + 1 keys, k and data
    if len(stack) < will_use:
        raise MissingStackItems('OP_DATA_MATCH_VALUE: need {} elements on stack, currently {}'
                                .format(will_use, len(stack)))

    items = {}
    try:
        for _ in range(n_items):
            pubkey = stack.pop()
            buf = stack.pop()
            value = binary_to_int(buf)
            items[value] = pubkey
    except (ValueError, struct.error) as e:
        raise VerifyFailed from e

    # one pubkey is left on stack
    last_pubkey = stack.pop()
    # next two items are data index and data
    data_k = stack.pop()
    data_k_int = data_k[0]      # data_k is a 1-byte unsigned int
    data = stack.pop()
    data_value = get_data_value(data_k_int, data)
    data_int = binary_to_int(data_value)
    winner_pubkey = items.get(data_int, last_pubkey)
    stack.append(winner_pubkey)


def op_find_p2pkh(stack, log, extras):
    """Checks whether the current transaction has an output with a P2PKH script with
    the given public key hash and the same amount as the input.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :param tx: Transaction to be added
    :type tx: :py:class:`hathor.transaction.BaseTransaction`

    :param contract_value: amount available on the nano contract (on the original output)
    :type contract_type: int

    :raises MissingStackItems: if stack is empty
    :raises VerifyFailed: verification failed
    """
    if not len(stack):
        raise MissingStackItems('OP_FIND_P2PKH: empty stack')

    spent_tx = extras.spent_tx
    txin = extras.txin
    tx = extras.tx
    contract_value = spent_tx.outputs[txin.index].value

    address = stack.pop()
    address_b58 = get_address_b58_from_bytes(address)
    for output in tx.outputs:
        p2pkh_out = P2PKH.verify_script(output.script)
        if p2pkh_out:
            if p2pkh_out.address == address_b58 and output.value == contract_value:
                stack.append(1)
                return
    # didn't find any match
    raise VerifyFailed


MAP_OPCODE_TO_FN = {
    Opcode.OP_DUP: op_dup,
    Opcode.OP_EQUALVERIFY: op_equalverify,
    Opcode.OP_CHECKSIG: op_checksig,
    Opcode.OP_HASH160: op_hash160,
    Opcode.OP_GREATERTHAN_TIMESTAMP: op_greaterthan_timestamp,
}
