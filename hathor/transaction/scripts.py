from enum import IntEnum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from hathor.crypto.util import get_hash160, get_public_key_from_bytes, \
                               get_public_key_bytes, get_address_b58_from_bytes, \
                               get_address_b58_from_public_key_bytes

# TODO what are we using for the signature?
DATA_TO_SIGN = b'DATA_TO_SIGN'


class Opcode(IntEnum):
    OP_DUP = 0x76
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xAC
    OP_HASH160 = 0xA9
    OP_PUSHDATA1 = 0x4C


class HathorScript:
    """This class is supposes to being a helper creating the scripts. It abstracts
    some of the corner cases when building the script.

    For eg, when pushing data to the stack, we may or may not have to use OP_PUSHDATA.
    This is the sequence we have to add to the script:
    - len(data) <= 75: [len(data) data]
    - len(data) > 75: [OP_PUSHDATA1 len(data) data]

    pushData abstracts this differences and presents an unique interface.
    """
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
        :type address: bytes
        """
        self.address = address

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
    def create_input_data(cls, private_key):
        """
        :param private_key: key corresponding to the address we want to spend tokens from
        :type private_key: :py:class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`

        :rtype: bytes
        """
        public_key_bytes = get_public_key_bytes(private_key.public_key())
        signature = private_key.sign(DATA_TO_SIGN, ec.ECDSA(hashes.SHA256()))
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
        address = get_address_b58_from_public_key_bytes(public_key)
        return cls(address)


def script_eval(output_script, input_data):
    """Evaluates the output script and input data according to
    a very limited subset of Bitcoin's scripting language.

    :param output_script: the script in the tx output
    :type output_script: bytes

    :param input_data: the tx input data
    :type input_data: bytes

    :return: True if valid, otherwise False + error string
    :rtype: (Boolean, string or None)
    """
    stack = []
    # merge input_data and output_script
    full_data = input_data + output_script
    data_len = len(full_data)
    pos = 0
    ret = True
    err = None
    while pos < len(full_data):
        opcode = full_data[pos]
        if (opcode >= 1 and opcode <= 75):
            # this is a pushdata opcode, indicating data length
            if (pos + opcode) > data_len:
                ret = False
                err = 'PUSHDATA overruns script script length'
                break
            pos += 1
            stack.append(full_data[pos:pos+opcode])
            pos += opcode
            continue
        elif opcode == Opcode.OP_PUSHDATA1:
            if pos >= len(full_data):
                ret = False
                err = 'PUSHDATA overruns script script length'
                break
            pos += 1
            length = full_data[pos]
            pos += 1
            stack.append(full_data[pos:pos+length])
            pos += length
            continue

        # this is an opcode manipulating the stack
        if opcode == Opcode.OP_DUP:
            if not len(stack):
                err = 'OP_DUP: empty stack'
                ret = False
                break
            stack.append(stack[-1])
        elif opcode == Opcode.OP_EQUALVERIFY:
            if len(stack) < 2:
                err = 'OP_EQUALVERIFY: need 2 elements on stack, currently {}'.format(len(stack))
                ret = False
                break
            elem1 = stack.pop()
            elem2 = stack.pop()
            if elem1 != elem2:
                err = 'OP_EQUALVERIFY: failed'
                ret = False
                break
        elif opcode == Opcode.OP_CHECKSIG:
            if len(stack) < 2:
                err = 'OP_EQUALVERIFY: need 2 elements on stack, currently {}'.format(len(stack))
                ret = False
                break
            pubkey = stack.pop()
            signature = stack.pop()
            public_key = get_public_key_from_bytes(pubkey)
            try:
                public_key.verify(signature, DATA_TO_SIGN, ec.ECDSA(hashes.SHA256()))
                # valid, push true to stack
                stack.append(1)
            except InvalidSignature:
                # invalid, push false to stack
                err = 'OP_CHECKSIG: failed'
                stack.append(0)
        elif opcode == Opcode.OP_HASH160:
            if not len(stack):
                err = 'OP_HASH160: empty stack'
                ret = False
                break
            elem1 = stack.pop()
            new_elem = get_hash160(elem1)
            stack.append(new_elem)
        else:
            # throw error
            err = 'unhandled opcode'
            ret = False
            break

        pos += 1
    if len(stack) > 0:
        if stack.pop() != 1:
            # stack left with non zero value
            err = 'value left on stack is not true'
            ret = False
    return (ret, err)
