from enum import IntEnum
from collections import namedtuple
import struct
import hashlib

from twisted.logger import Logger

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from hathor.crypto.util import get_hash160, get_public_key_from_bytes_compressed, \
                               get_address_b58_from_bytes, get_address_b58_from_public_key_bytes_compressed
from hathor.transaction.exceptions import ScriptError, OutOfData, MissingStackItems, \
                                          EqualVerifyFailed, FinalStackInvalid, TimeLocked


ScriptExtras = namedtuple('ScriptExtras', 'tx txin spent_tx')


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
    def __init__(self, address):
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
        """
        self.address = address

    def to_human_readable(self):
        ret = {}
        ret['type'] = 'P2PKH'
        ret['address'] = self.address
        return ret

    @classmethod
    def create_output_script(cls, address):
        """
        :param address: address to send tokens
        :type address: bytes

        :rtype: bytes
        """
        # return struct.pack(
        #     '!BBB{}sBB'.format(len(address)),
        #     Opcode.OP_DUP,
        #     Opcode.OP_HASH160,
        #     len(address),
        #     address,
        #     Opcode.OP_EQUALVERIFY,
        #     Opcode.OP_CHECKSIG
        # )
        s = HathorScript()
        s.addOpcode(Opcode.OP_DUP)
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(address)
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
        # return struct.pack(
        #     '!B{}sB{}s'.format(len(signature), len(public_key_bytes)),
        #     len(signature),
        #     signature,
        #     len(public_key_bytes),
        #     public_key_bytes
        # )
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
        if (
            script[0] == Opcode.OP_DUP
            and script[1] == Opcode.OP_HASH160
            and script[-2] == Opcode.OP_EQUALVERIFY
            and script[-1] == Opcode.OP_CHECKSIG
        ):
            pos = 2
            if script[2] > 75:
                pos = 3
            size = script[pos]
            address = script[pos+1:size+pos+1]
            address_b58 = get_address_b58_from_bytes(address)
            return cls(address_b58)
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


def script_eval(output_script, input_data, tx, txin, spent_tx):
    """Evaluates the output script and input data according to
    a very limited subset of Bitcoin's scripting language.

    :param output_script: the script in the tx output
    :type output_script: bytes

    :param input_data: the tx input data
    :type input_data: bytes

    :raises ScriptError: if script verification fails
    """
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

    :raises OutOfData: if can't read data to be pushed

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

    :raises OutOfData: if can't read data to be pushed

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
        raise TimeLocked('tx.timestamp ({}) < {}'.format(extras.tx.timestamp, timelock))


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


MAP_OPCODE_TO_FN = {
    Opcode.OP_DUP: op_dup,
    Opcode.OP_EQUALVERIFY: op_equalverify,
    Opcode.OP_CHECKSIG: op_checksig,
    Opcode.OP_HASH160: op_hash160,
    Opcode.OP_GREATERTHAN_TIMESTAMP: op_greaterthan_timestamp,
}
