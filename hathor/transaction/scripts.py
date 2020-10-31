# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import datetime
import re
import struct
from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Any, Callable, Dict, Generator, List, NamedTuple, Optional, Pattern, Type, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf import HathorSettings
from hathor.crypto.util import (
    decode_address,
    get_address_b58_from_bytes,
    get_address_b58_from_public_key_hash,
    get_address_b58_from_redeem_script_hash,
    get_hash160,
    get_public_key_from_bytes_compressed,
    is_pubkey_compressed,
)
from hathor.transaction import BaseTransaction, Transaction, TxInput
from hathor.transaction.exceptions import (
    DataIndexError,
    EqualVerifyFailed,
    FinalStackInvalid,
    InvalidScriptError,
    InvalidStackData,
    MissingStackItems,
    OracleChecksigFailed,
    OutOfData,
    ScriptError,
    TimeLocked,
    VerifyFailed,
)

settings = HathorSettings()

# XXX: Because the Stack is a heterogeneous list of bytes and int, and some OPs only work for when the stack has some
#      or the other type, there are many places that require an assert to prevent the wrong type from being used,
#      alternatives include: 1. only using `List[bytes]` and operations that work on `int` to build them from `bytes`,
#      2. using `bytearray` instead of `List[...]` and using type codes on the stack or at least value sizes on the
#      stack and OPs should use the extra info accordingly 3. using some "in stack error" at least custom exceptions
#      for signaling that an OP was applied on a wrongly typed stack.
Stack = List[Union[bytes, int, str]]


class ScriptExtras(NamedTuple):
    tx: Transaction
    txin: TxInput
    spent_tx: BaseTransaction


class OpcodePosition(NamedTuple):
    opcode: int
    position: int


def re_compile(pattern: str) -> Pattern[bytes]:
    """ Transform a given script pattern into a regular expression.

    The script pattern is like a regular expression, but you may include five
    special symbols:
      (i) OP_DUP, OP_HASH160, and all other opcodes;
     (ii) DATA_<length>: data with the specified length;
    (iii) NUMBER: a 4-byte integer;
     (iv) BLOCK: a variable length block, to be parsed later

    Example:
    >>> r = re_compile(
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
        elif x.startswith('NUMBER'):
            return b'.{5}'
        elif x.startswith('BLOCK'):
            return b'.*'
        else:
            raise ValueError('Invalid opcode: {}'.format(x))

    p = pattern.encode('ascii')
    p = re.sub(rb'\s*([A-Z0-9_]+)\s*', _to_byte_pattern, p)
    return re.compile(p, re.DOTALL)


def _re_pushdata(length: int) -> bytes:
    """ Create a regular expression that matches a data block with a given length.

    :return: A non-compiled regular expression
    :rtype: bytes
    """
    ret = [bytes([Opcode.OP_PUSHDATA1]), bytes([length]), b'.{', str(length).encode('ascii'), b'}']

    if length <= 75:
        # for now, we accept <= 75 bytes with OP_PUSHDATA1. It's optional
        ret.insert(1, b'?')

    return b''.join(ret)


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


class HathorScript:
    """This class is supposed to be help build scripts abstracting some corner cases.

    For example, when pushing data to the stack, we may or may not have to use OP_PUSHDATA.
    This is the sequence we have to add to the script:
    - len(data) <= 75: [len(data) data]
    - len(data) > 75: [OP_PUSHDATA1 len(data) data]

    pushData abstracts this differences and presents an unique interface.
    """
    def __init__(self) -> None:
        self.data = b''

    def addOpcode(self, opcode: Opcode) -> None:
        self.data += bytes([opcode])

    def pushData(self, data: Union[int, bytes]) -> None:
        if isinstance(data, int):
            if data > 4294967295:
                n = struct.pack('!Q', data)
            elif data > 65535:
                n = struct.pack('!I', data)
            elif data > 255:
                n = struct.pack('!H', data)
            else:
                n = struct.pack('!B', data)
            data = n
        if len(data) <= 75:
            self.data += (bytes([len(data)]) + data)
        else:
            self.data += (bytes([Opcode.OP_PUSHDATA1]) + bytes([len(data)]) + data)


class BaseScript(ABC):
    """
    This class holds common methods for different script types to help abstracting the script type.
    """

    @abstractmethod
    def to_human_readable(self) -> Dict[str, Any]:
        """Return a nice dict for using on informational json APIs."""
        raise NotImplementedError

    @abstractmethod
    def get_type(self) -> str:
        """Get script type name"""
        raise NotImplementedError

    @abstractmethod
    def get_script(self) -> bytes:
        """Get or build script"""
        raise NotImplementedError

    @abstractmethod
    def get_address(self) -> Optional[str]:
        """Get address for this script, not all valid recognizable scripts have addresses."""
        raise NotImplementedError

    @abstractmethod
    def get_timelock(self) -> Optional[int]:
        """Get timelock for this script, completely optional."""
        raise NotImplementedError


class P2PKH(BaseScript):
    re_match = re_compile('^(?:(DATA_4) OP_GREATERTHAN_TIMESTAMP)? '
                          'OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKSIG$')

    def __init__(self, address: str, timelock: Optional[int] = None) -> None:
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

    def to_human_readable(self) -> Dict[str, Any]:
        ret: Dict[str, Any] = {}
        ret['type'] = self.get_type()
        ret['address'] = self.address
        ret['timelock'] = self.timelock
        return ret

    def get_type(self) -> str:
        return 'P2PKH'

    def get_script(self) -> bytes:
        return P2PKH.create_output_script(decode_address(self.address), self.timelock)

    def get_address(self) -> Optional[str]:
        return self.address

    def get_timelock(self) -> Optional[int]:
        return self.timelock

    @classmethod
    def create_output_script(cls, address: bytes, timelock: Optional[Any] = None) -> bytes:
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
    def create_input_data(cls, public_key_bytes: bytes, signature: bytes) -> bytes:
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
    def parse_script(cls, script: bytes) -> Optional['P2PKH']:
        """Checks if the given script is of type p2pkh. If it is, returns the P2PKH object.
        Otherwise, returns None.

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
            public_key_hash = get_pushdata(pushdata_address)
            address_b58 = get_address_b58_from_public_key_hash(public_key_hash)
            return cls(address_b58, timelock)
        return None


class MultiSig(BaseScript):
    re_match = re_compile('^(?:(DATA_4) OP_GREATERTHAN_TIMESTAMP)? ' 'OP_HASH160 (DATA_20) OP_EQUAL$')

    def __init__(self, address: str, timelock: Optional[Any] = None) -> None:
        """This class represents the multi signature script (MultiSig). It enables the group of persons
        who has the corresponding private keys of the address to spend the tokens.

        This script validates the signatures and public keys on the corresponding input
        data.

        Output script and the corresponding input data are usually represented like:
        output script: OP_HASH160 <redeemScriptHash> OP_EQUAL
        input data: <sig1> ... <sigM> <redeemScript>

        :param address: address to send tokens
        :type address: string(base58)

        :param timelock: timestamp until when it's locked
        :type timelock: int
        """
        self.address = address
        self.timelock = timelock

    def to_human_readable(self) -> Dict[str, Any]:
        """ Decode MultiSig class to dict with its type and data

            :return: Dict with MultiSig info
            :rtype: Dict[str:]
        """
        ret: Dict[str, Any] = {}
        ret['type'] = self.get_type()
        ret['address'] = self.address
        ret['timelock'] = self.timelock
        return ret

    def get_type(self) -> str:
        return 'MultiSig'

    def get_script(self) -> bytes:
        return MultiSig.create_output_script(decode_address(self.address), self.timelock)

    def get_address(self) -> Optional[str]:
        return self.address

    def get_timelock(self) -> Optional[int]:
        return self.timelock

    @classmethod
    def get_multisig_redeem_script_pos(cls, input_data: bytes) -> int:
        """ Get the position of the opcode that pushed the redeem_script on the stack

        :param input_data: data from the input being evaluated
        :type input_data: bytes

        :return: position of pushdata for redeem_script
        :rtype: int
        """
        pos = 0
        last_pos = 0
        data_len = len(input_data)
        while pos < data_len:
            last_pos = pos
            _, pos = get_script_op(pos, input_data)
        return last_pos

    @classmethod
    def create_output_script(cls, address: bytes, timelock: Optional[Any] = None) -> bytes:
        """
        :param address: address to send tokens
        :type address: bytes

        :param timelock: timestamp until when the output is locked
        :type timelock: bytes

        :rtype: bytes
        """
        assert len(address) == 25
        redeem_script_hash = address[1:-4]
        s = HathorScript()
        if timelock:
            s.pushData(timelock)
            s.addOpcode(Opcode.OP_GREATERTHAN_TIMESTAMP)
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(redeem_script_hash)
        s.addOpcode(Opcode.OP_EQUAL)
        return s.data

    @classmethod
    def create_input_data(cls, redeem_script: bytes, signatures: List[bytes]) -> bytes:
        """
        :param redeem_script: script to redeem the tokens: <M> <pubkey1> ... <pubkeyN> <N> <OP_CHECKMULTISIG>
        :type redeem_script: bytes

        :param signatures: array of signatures to validate the input and redeem the tokens
        :type signagures: List[bytes]

        :rtype: bytes
        """
        s = HathorScript()
        for signature in signatures:
            s.pushData(signature)
        s.pushData(redeem_script)
        return s.data

    @classmethod
    def parse_script(cls, script: bytes) -> Optional['MultiSig']:
        """Checks if the given script is of type multisig. If it is, returns the MultiSig object.
        Otherwise, returns None.

        :param script: script to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.MultiSig` or None
        """
        match = cls.re_match.search(script)
        if match:
            groups = match.groups()
            timelock = None
            pushdata_timelock = groups[0]
            if pushdata_timelock:
                timelock_bytes = pushdata_timelock[1:]
                timelock = struct.unpack('!I', timelock_bytes)[0]
            redeem_script_hash = get_pushdata(groups[1])
            address_b58 = get_address_b58_from_redeem_script_hash(redeem_script_hash)
            return cls(address_b58, timelock)
        return None

    @classmethod
    def get_multisig_data(cls, input_data: bytes) -> bytes:
        """ Input data has many signatures and a block with the redeem script
            In the second part of the script eval we need to evaluate the redeem script
            so we need to get the redeem script without the block, to evaluate the elements on it

            This method removes the (possible) OP_PUSHDATA1 byte and the redeem script length,
            so it can be evaluated as any normal script

            :param input_data: data from the input being evaluated
            :type input_data: bytes

            :return: data ready to be evaluated. The signatures and the redeem script
            :rtype: bytes
        """
        pos = 0
        last_pos = 0
        stack: Stack = []
        data_len = len(input_data)
        while pos < data_len:
            last_pos = pos
            opcode = input_data[pos]
            if (opcode >= 1 and opcode <= 75):
                pos = op_pushdata(pos, input_data, stack)
            elif opcode == Opcode.OP_PUSHDATA1:
                pos = op_pushdata1(pos, input_data, stack)
            else:
                pos += 1

        redeem_script = stack[-1]
        assert isinstance(redeem_script, bytes)
        return input_data[:last_pos] + redeem_script


# XXX: does it make sense to make this BaseScript too?
class NanoContractMatchValues:
    re_match = re_compile('^OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKDATASIG OP_0 (BLOCK) OP_DATA_STREQUAL '
                          'OP_1 (NUMBER) OP_DATA_GREATERTHAN OP_2 (BLOCK) OP_DATA_MATCH_VALUE OP_FIND_P2PKH$')

    def __init__(self, oracle_pubkey_hash, min_timestamp, oracle_data_id, value_dict, fallback_pubkey_hash=b'\x00'):
        """This class represents a nano contract that tries to match on a single value. The pubKeyHash
        associated with the data given by the oracle will be able to spend the contract tokens.

        :param oracle_pubkey_hash: oracle's public key after being hashed by SHA256 and RIPMD160
        :type oracle_pubkey_hash: bytes

        :param min_timestamp: contract can only be spent after this timestamp. If we don't need it, simply
        pass same timestamp as transaction
        :type min_timestamp: int

        :param oracle_data_id: unique id for the data reported by the oracle. For eg, a oracle that reports
        stock prices can use stock ticker symbols as this id
        :type oracle_data_id: bytes

        :param value_dict: a dictionary with the pubKeyHash and corresponding value ({pubKeyHash, value}).
        The pubkeyHash with value matching the data sent by oracle will be able to spend the contract funds
        :type value_dict: Dict[bytes, int]

        :param fallback_pubkey_hash: if none of the values match, this pubkey hash identifies the winner address
        :type fallback_pubkey_hash: bytes
        """
        self.oracle_pubkey_hash = oracle_pubkey_hash
        self.min_timestamp = min_timestamp
        self.oracle_data_id = oracle_data_id
        self.value_dict = value_dict  # Dict[bytes, int]
        self.fallback_pubkey_hash = fallback_pubkey_hash

    def to_human_readable(self) -> Dict[str, Any]:
        ret: Dict[str, Any] = {}
        ret['type'] = 'NanoContractMatchValues'
        ret['oracle_pubkey_hash'] = base64.b64encode(self.oracle_pubkey_hash).decode('utf-8')
        ret['min_timestamp'] = self.min_timestamp
        ret['oracle_data_id'] = self.oracle_data_id.decode('utf-8')
        ret['value_dict'] = {get_address_b58_from_bytes(k): v for k, v in self.value_dict.items()}
        try:
            if len(self.fallback_pubkey_hash) == 1:
                ret['fallback_pubkey_hash'] = None
            else:
                ret['fallback_pubkey_hash'] = get_address_b58_from_bytes(self.fallback_pubkey_hash)
        except TypeError:
            ret['fallback_pubkey_hash'] = None
        return ret

    def create_output_script(self) -> bytes:
        """
        :return: the output script in binary
        :rtype: bytes
        """
        s = HathorScript()
        s.addOpcode(Opcode.OP_DUP)
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(self.oracle_pubkey_hash)
        s.addOpcode(Opcode.OP_EQUALVERIFY)
        s.addOpcode(Opcode.OP_CHECKDATASIG)
        # compare first value from data with oracle_data_id
        s.addOpcode(Opcode.OP_0)
        s.pushData(self.oracle_data_id)
        s.addOpcode(Opcode.OP_DATA_STREQUAL)
        # compare second value from data with min_timestamp
        s.addOpcode(Opcode.OP_1)
        s.pushData(struct.pack('!I', self.min_timestamp))
        s.addOpcode(Opcode.OP_DATA_GREATERTHAN)
        # finally, compare third value with values on dict
        s.addOpcode(Opcode.OP_2)
        s.pushData(self.fallback_pubkey_hash)
        for pubkey_hash, value in self.value_dict.items():
            s.pushData(value)
            s.pushData(pubkey_hash)
        # we use int as bytes because it may be greater than 16
        # TODO should we limit it to 16?
        s.pushData(len(self.value_dict))
        s.addOpcode(Opcode.OP_DATA_MATCH_VALUE)
        # pubkey left on stack should be on outputs
        s.addOpcode(Opcode.OP_FIND_P2PKH)
        return s.data

    @classmethod
    def create_input_data(cls, data: bytes, oracle_sig: bytes, oracle_pubkey: bytes) -> bytes:
        """
        :param data: data from the oracle
        :type data: bytes

        :param oracle_sig: the data signed by the oracle, with its private key
        :type oracle_sig: bytes

        :param oracle_pubkey: the oracle's public key
        :type oracle_pubkey: bytes

        :rtype: bytes
        """
        s = HathorScript()
        s.pushData(data)
        s.pushData(oracle_sig)
        s.pushData(oracle_pubkey)
        return s.data

    @classmethod
    def parse_script(cls, script: bytes) -> Optional['NanoContractMatchValues']:
        """Checks if the given script is of type NanoContractMatchValues. If it is, returns the corresponding object.
        Otherwise, returns None.

        :param script: script to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.NanoContractMatchValues` or None
        """
        # regex for this is a bit tricky, as some data has variable length. We first match the base regex for this
        # script and later manually parse variable length fields
        match = cls.re_match.search(script)
        if match:
            groups = match.groups()
            # oracle pubkey hash
            oracle_pubkey_hash = get_pushdata(groups[0])
            # oracle data id
            oracle_data_id = get_pushdata(groups[1])
            # timestamp
            timestamp = groups[2]
            min_timestamp = binary_to_int(timestamp[1:])

            # variable length data. We'll parse it manually. It should have the following format:
            # fallback_pubkey_hash, [valueN, pubkey_hash_N], N
            extra_data = groups[3]

            fallback_pubkey_len = extra_data[0]
            if len(extra_data) < fallback_pubkey_len + 2:
                # extra data has at least the fallback_pubkey length (1 byte) and number of
                # values (N, after values and pubkeys). That's why we use fallback_pubkey_len + 2
                return None
            fallback_pubkey = extra_data[1] if fallback_pubkey_len == 1 else extra_data[1:fallback_pubkey_len]
            n_values = extra_data[-1]

            values_pubkeys = extra_data[(fallback_pubkey_len + 1):-2]
            value_dict = {}
            pos = 0
            for i in range(n_values):
                if len(values_pubkeys[pos:]) < 1:
                    return None
                value_len = values_pubkeys[pos]
                pos += 1
                if len(values_pubkeys[pos:]) < value_len:
                    return None
                value = values_pubkeys[pos] if value_len == 1 else binary_to_int(values_pubkeys[pos:(pos + value_len)])
                pos += value_len
                if len(values_pubkeys[pos:]) < 1:
                    return None
                pubkey_len = values_pubkeys[pos]
                pos += 1
                if len(values_pubkeys[pos:]) < pubkey_len:
                    return None
                pubkey = values_pubkeys[pos:(pos + pubkey_len)]
                pos += pubkey_len
                value_dict[pubkey] = value

            if len(values_pubkeys[pos:]) > 0:
                # shouldn't have data left
                return None

            return NanoContractMatchValues(oracle_pubkey_hash, min_timestamp, oracle_data_id, value_dict,
                                           fallback_pubkey)
        return None


def create_base_script(address: str, timelock: Optional[Any] = None) -> BaseScript:
    """ Verifies if address is P2PKH or Multisig and return the corresponding BaseScript implementation.
    """
    baddress = decode_address(address)
    if baddress[0] == binary_to_int(settings.P2PKH_VERSION_BYTE):
        return P2PKH(address, timelock)
    elif baddress[0] == binary_to_int(settings.MULTISIG_VERSION_BYTE):
        return MultiSig(address, timelock)
    else:
        raise ScriptError('The address is not valid')


def create_output_script(address: bytes, timelock: Optional[Any] = None) -> bytes:
    """ Verifies if address is P2PKH or Multisig and create correct output script

        :param address: address to send tokens
        :type address: bytes

        :param timelock: timestamp until when the output is locked
        :type timelock: bytes

        :raises ScriptError: if address is not from one of the possible options

        :rtype: bytes
    """
    # XXX: if the address class can somehow be simplified create_base_script could be used here
    if address[0] == binary_to_int(settings.P2PKH_VERSION_BYTE):
        return P2PKH.create_output_script(address, timelock)
    elif address[0] == binary_to_int(settings.MULTISIG_VERSION_BYTE):
        return MultiSig.create_output_script(address, timelock)
    else:
        raise ScriptError('The address is not valid')


def parse_address_script(script: bytes) -> Optional[Union[P2PKH, MultiSig]]:
    """ Verifies if address is P2PKH or Multisig and calls correct parse_script method

        :param script: script to decode
        :type script: bytes

        :return: P2PKH or MultiSig class or None
        :rtype: class or None
    """
    script_classes: List[Type[Union[P2PKH, MultiSig]]] = [P2PKH, MultiSig]
    # Each class verifies its script
    for script_class in script_classes:
        if script_class.re_match.search(script):
            return script_class.parse_script(script)
    return None


def decode_opn(opcode: int) -> int:
    """ Decode integer opcode (OP_N) to its integer value

        :param opcode: the opcode to convert
        :type opcode: bytes

        :raises InvalidScriptError: case opcode is not a valid OP_N

        :return: int value for opcode param
        :rtype: int
    """
    int_val = opcode - Opcode.OP_0
    if not (0 <= int_val <= 16):
        raise InvalidScriptError('unknown opcode {}'.format(opcode))
    return int_val


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


class _ScriptOperation(NamedTuple):
    opcode: Union[Opcode, int]
    position: int
    data: Union[None, bytes, int, str]


def parse_script_ops(data: bytes) -> Generator[_ScriptOperation, None, None]:
    """ Parse script yielding each operation on the script
        this is an utility function to make scripts human readable for debugging and dev

        :param data: script to parse that contains data and opcodes
        :type data: bytes

        :return: generator for operations on script
        :rtype: Generator[_ScriptOperation, None, None]
    """
    op: Union[Opcode, int]

    pos = 0
    last_pos = 0
    data_len = len(data)
    stack: Stack = []
    while pos < data_len:
        last_pos = pos
        opcode, pos = get_script_op(pos, data, stack)
        try:
            op = Opcode(opcode)
        except ValueError:
            op = opcode
        if len(stack) != 0:
            yield _ScriptOperation(opcode=op, position=last_pos, data=stack.pop())
        else:
            yield _ScriptOperation(opcode=op, position=last_pos, data=None)


def count_sigops(data: bytes) -> int:
    """ Count number of signature operations on the script

        :param data: script to parse that contains data and opcodes
        :type data: bytes

        :raises OutOfData: when trying to read out of script
        :raises InvalidScriptError: when an invalid opcode is found
        :raises InvalidScriptError: when the previous opcode to an
                OP_CHECKMULTISIG is not an integer (number of operations to execute)

        :return: number of signature operations the script would do if it was executed
        :rtype: int
    """
    n_ops: int = 0
    data_len: int = len(data)
    pos: int = 0
    last_opcode: Union[int, None] = None

    while pos < data_len:
        opcode, pos = get_script_op(pos, data)

        if opcode == Opcode.OP_CHECKSIG:
            n_ops += 1
        elif opcode == Opcode.OP_CHECKMULTISIG:
            assert isinstance(last_opcode, int)
            if Opcode.OP_0 <= last_opcode <= Opcode.OP_16:
                # Conventional OP_CHECKMULTISIG: <sign_1>...<sign_m> <m> <pubkey_1>...<pubkey_n> <n> <checkmultisig>
                # this function will run op_checksig with each pair (sign_x, pubkey_y) until all signatures
                # are verified so the worst case scenario is n op_checksig and the best m op_checksig
                # we know m <= n, so for now we are counting n operations (the upper limit)
                n_ops += decode_opn(last_opcode)
            else:
                # Unconventional OP_CHECKMULTISIG:
                # We count the limit for PUBKEYS, since this is also the upper limit on signature operations
                # that any op_checkmultisig would run
                n_ops += settings.MAX_MULTISIG_PUBKEYS
        last_opcode = opcode
    return n_ops


def get_sigops_count(data: bytes, output_script: Optional[bytes] = None) -> int:
    """ Count number of signature operations on the script, if it's an input script and the spent output is passed
        check the spent output for MultiSig and count operations on redeem_script too

        :param data: script to parse with opcodes
        :type data: bytes

        :param output_script: spent output script if data was from an TxIn
        :type output_script: Union[None, bytes]

        :raises OutOfData: when trying to read out of script
        :raises InvalidScriptError: when an invalid opcode is found

        :return: number of signature operations the script would do if it was executed
        :rtype: int
    """
    # If validating an input, should check the spent_tx for MultiSig
    if output_script is not None:
        # If it's multisig we have to validate the redeem_script sigop count
        if MultiSig.re_match.search(output_script):
            multisig_data = MultiSig.get_multisig_data(data)
            # input_script + redeem_script
            return count_sigops(multisig_data)

    return count_sigops(data)


def execute_eval(data: bytes, log: List[str], extras: ScriptExtras) -> None:
    """ Execute eval from data executing opcode methods

        :param data: data to be evaluated that contains data and opcodes
        :type data: bytes

        :param log: List of log messages
        :type log: List[str]

        :param extras: namedtuple with extra fields
        :type extras: :py:class:`hathor.transaction.scripts.ScriptExtras`

        :raises ScriptError: case opcode is not found
        :raises FinalStackInvalid: case the evaluation fails
    """
    stack: Stack = []
    data_len = len(data)
    pos = 0
    while pos < data_len:
        opcode, pos = get_script_op(pos, data, stack)
        if Opcode.is_pushdata(opcode):
            continue
        # this is an opcode manipulating the stack
        fn = MAP_OPCODE_TO_FN.get(opcode, None)
        if fn is None:
            # throw error
            raise ScriptError('unknown opcode')

        fn(stack, log, extras)

    evaluate_final_stack(stack, log)


def evaluate_final_stack(stack: Stack, log: List[str]) -> None:
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


def script_eval(tx: Transaction, txin: TxInput, spent_tx: BaseTransaction) -> None:
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
    log: List[str] = []
    extras = ScriptExtras(tx=tx, txin=txin, spent_tx=spent_tx)

    if MultiSig.re_match.search(output_script):
        # For MultiSig there are 2 executions:
        # First we need to evaluate that redeem_script matches redeem_script_hash
        # we can't use input_data + output_script because it will end with an invalid stack
        # i.e. the signatures will still be on the stack after ouput_script is executed
        redeem_script_pos = MultiSig.get_multisig_redeem_script_pos(input_data)
        full_data = txin.data[redeem_script_pos:] + output_script
        execute_eval(full_data, log, extras)

        # Second, we need to validate that the signatures on the input_data solves the redeem_script
        # we pop and append the redeem_script to the input_data and execute it
        multisig_data = MultiSig.get_multisig_data(extras.txin.data)
        execute_eval(multisig_data, log, extras)
    else:
        # merge input_data and output_script
        full_data = input_data + output_script
        execute_eval(full_data, log, extras)


def get_pushdata(data: bytes) -> bytes:
    if data[0] > 75:
        length = data[1]
        start = 2
    else:
        length = data[0]
        start = 1
    return data[start:(start + length)]


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


def op_pushdata(position: int, full_data: bytes, stack: Stack) -> int:
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
    :type stack: List[]

    :raises OutOfData: if data length to read is larger than what's available

    :return: new position to be read from full_data
    :rtype: int
    """
    opcode, new_pos = get_script_op(position, full_data, stack)
    assert opcode == Opcode.OP_PUSHDATA1
    return new_pos


def op_dup(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Duplicates item on top of stack

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(stack):
        raise MissingStackItems('OP_DUP: empty stack')
    stack.append(stack[-1])


def op_greaterthan_timestamp(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Check whether transaction's timestamp is greater than the top of stack

    The top of stack must be a big-endian u32int.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(stack):
        raise MissingStackItems('OP_GREATERTHAN_TIMESTAMP: empty stack')
    buf = stack.pop()
    assert isinstance(buf, bytes)
    (timelock,) = struct.unpack('!I', buf)
    if extras.tx.timestamp <= timelock:
        raise TimeLocked('The output is locked until {}'.format(
            datetime.datetime.fromtimestamp(timelock).strftime("%m/%d/%Y %I:%M:%S %p")))


def op_equalverify(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Verifies top 2 elements from stack are equal

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 2 element on stack
    :raises EqualVerifyFailed: items don't match
    """
    if len(stack) < 2:
        raise MissingStackItems('OP_EQUALVERIFY: need 2 elements on stack, currently {}'.format(len(stack)))
    op_equal(stack, log, extras)
    is_equal = stack.pop()
    if not is_equal:
        raise EqualVerifyFailed('Failed to verify if elements are equal')


def op_equal(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Verifies top 2 elements from stack are equal

    In case they are the same, we push 1 to the stack and push 0 if they are different

    :param stack: the stack used when evaluating the script
    :type stack: List[]
    """
    if len(stack) < 2:
        raise MissingStackItems('OP_EQUAL: need 2 elements on stack, currently {}'.format(len(stack)))
    elem1 = stack.pop()
    elem2 = stack.pop()
    assert isinstance(elem1, bytes)
    assert isinstance(elem2, bytes)
    if elem1 == elem2:
        stack.append(1)
    else:
        stack.append(0)
        log.append('OP_EQUAL: failed. elements: {} {}'.format(elem1.hex(), elem2.hex()))


def op_checksig(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Verifies public key and signature match. Expects public key to be on top of stack, followed
    by signature. If they match, put 1 on stack (meaning True); otherwise, push 0 (False)

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 2 element on stack
    :raises ScriptError: if pubkey on stack is not a compressed public key

    :return: if they don't match, return error message
    :rtype: string
    """
    if len(stack) < 2:
        raise MissingStackItems('OP_CHECKSIG: need 2 elements on stack, currently {}'.format(len(stack)))
    pubkey = stack.pop()
    signature = stack.pop()
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
        public_key.verify(signature, extras.tx.get_sighash_all_data(), ec.ECDSA(hashes.SHA256()))
        # valid, push true to stack
        stack.append(1)
    except InvalidSignature:
        # invalid, push false to stack
        stack.append(0)
        log.append('OP_CHECKSIG: failed')


def op_hash160(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Top stack item is hashed twice: first with SHA-256 and then with RIPEMD-160.
    Result is pushed back to stack.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there's no element on stack
    """
    if not len(stack):
        raise MissingStackItems('OP_HASH160: empty stack')
    elem1 = stack.pop()
    assert isinstance(elem1, bytes)
    new_elem = get_hash160(elem1)
    stack.append(new_elem)


def op_checkdatasig(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
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
        stack.append(data)
    except InvalidSignature as e:
        raise OracleChecksigFailed from e


def op_data_strequal(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
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
    data = stack.pop()
    assert isinstance(value, bytes)
    assert isinstance(data, bytes)

    if not isinstance(data_k, int):
        raise VerifyFailed('OP_DATA_STREQUAL: value on stack should be an integer ({!r})'.format(data_k))

    data_value = get_data_value(data_k, data)
    if data_value != value:
        raise VerifyFailed('OP_DATA_STREQUAL: {} x {}'.format(data_value.decode('utf-8'), value.decode('utf-8')))

    stack.append(data)


def op_data_greaterthan(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
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
    data = stack.pop()
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

    stack.append(data)


def op_data_match_interval(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Equivalent to an OP_GET_DATA_INT followed by an OP_MATCH_INTERVAL.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

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


def op_data_match_value(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Equivalent to an OP_GET_DATA_STR followed by an OP_MATCH_VALUE.

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if there aren't 3 element on stack
    :raises VerifyFailed: verification failed
    """
    if len(stack) < 1:
        raise MissingStackItems('OP_DATA_MATCH_VALUE: empty stack')

    data_n_items = stack.pop()
    assert isinstance(data_n_items, bytes)
    # TODO test this can be transformed to integer
    n_items = data_n_items[0]

    # number of items in stack that will be used
    will_use = 2 * n_items + 3  # n data_points, n + 1 keys, k and data
    if len(stack) < will_use:
        raise MissingStackItems('OP_DATA_MATCH_VALUE: need {} elements on stack, currently {}'.format(
            will_use, len(stack)))

    items = {}
    try:
        for _ in range(n_items):
            pubkey = stack.pop()
            buf = stack.pop()
            assert isinstance(pubkey, (str, bytes))
            assert isinstance(buf, bytes)
            value = binary_to_int(buf)
            items[value] = pubkey
    except (ValueError, struct.error) as e:
        raise VerifyFailed from e

    # one pubkey is left on stack
    last_pubkey = stack.pop()
    # next two items are data index and data
    data_k = stack.pop()
    data = stack.pop()
    assert isinstance(data_k, int)
    assert isinstance(data, bytes)
    data_value = get_data_value(data_k, data)
    data_int = binary_to_int(data_value)
    winner_pubkey = items.get(data_int, last_pubkey)
    assert isinstance(winner_pubkey, (str, bytes))
    stack.append(winner_pubkey)


def op_find_p2pkh(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
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
        p2pkh_out = P2PKH.parse_script(output.script)
        if p2pkh_out:
            if p2pkh_out.address == address_b58 and output.value == contract_value:
                stack.append(1)
                return
    # didn't find any match
    raise VerifyFailed


def op_checkmultisig(stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """Checks if it has the minimum signatures required and if all of them are valid

    :param stack: the stack used when evaluating the script
    :type stack: List[]

    :raises MissingStackItems: if stack is empty or it has less signatures than the minimum required
    :raises VerifyFailed: verification failed
    """
    if not len(stack):
        raise MissingStackItems('OP_CHECKMULTISIG: empty stack')

    # Pop the quantity of pubkeys
    pubkey_count = stack.pop()

    if not isinstance(pubkey_count, int):
        raise InvalidStackData('OP_CHECKMULTISIG: pubkey count should be an integer')

    if pubkey_count > settings.MAX_MULTISIG_PUBKEYS:
        raise InvalidStackData('OP_CHECKMULTISIG: pubkey count ({}) exceeded the limit ({})'.format(
                pubkey_count,
                settings.MAX_MULTISIG_PUBKEYS,
                )
            )

    if len(stack) < pubkey_count:
        raise MissingStackItems('OP_CHECKMULTISIG: not enough public keys on the stack')

    # Get all pubkeys
    pubkeys = []
    for _ in range(pubkey_count):
        pubkey_bytes = stack.pop()
        pubkeys.append(pubkey_bytes)

    if not len(stack):
        raise MissingStackItems('OP_CHECKMULTISIG: less elements than should on the stack')

    # Pop the quantity of signatures required
    signatures_count = stack.pop()

    if not isinstance(signatures_count, int):
        raise InvalidStackData('OP_CHECKMULTISIG: signatures count should be an integer')

    if signatures_count > settings.MAX_MULTISIG_SIGNATURES:
        raise InvalidStackData('OP_CHECKMULTISIG: signature count ({}) exceeded the limit ({})'.format(
                signatures_count,
                settings.MAX_MULTISIG_SIGNATURES,
                )
            )

    # Error if we don't have the minimum quantity of signatures
    if len(stack) < signatures_count:
        raise MissingStackItems('OP_CHECKMULTISIG: not enough signatures on the stack')

    # Get all signatures
    signatures = []
    for _ in range(signatures_count):
        signature_bytes = stack.pop()
        signatures.append(signature_bytes)

    # For each signature we check if it's valid with one of the public keys
    # Signatures must be in order (same as the public keys in the multi sig wallet)
    pubkey_index = 0
    for signature in signatures:
        while pubkey_index < len(pubkeys):
            pubkey = pubkeys[pubkey_index]
            new_stack = [signature, pubkey]
            op_checksig(new_stack, log, extras)
            result = new_stack.pop()
            pubkey_index += 1
            if result == 1:
                break
        else:
            # finished all pubkeys and did not verify all signatures
            stack.append(0)
            return

    # If all signatures are valids we push 1
    stack.append(1)


def op_integer(opcode: int, stack: Stack, log: List[str], extras: ScriptExtras) -> None:
    """ Appends an integer to the stack
        We get the opcode comparing to all integers opcodes

        Example to append integer 4:
        opcode will be equal to OP_4 (0x54)
        Then we append the integer OP_4 - OP_0 = 4

        :param opcode: the opcode to append to the stack
        :type opcode: bytes

        :param stack: the stack used when evaluating the script
        :type stack: List[]
    """
    try:
        stack.append(decode_opn(opcode))
    except InvalidScriptError as e:
        raise ScriptError(e) from e


MAP_OPCODE_TO_FN: Dict[int, Callable[[Stack, List[str], ScriptExtras], None]] = {
    Opcode.OP_DUP: op_dup,
    Opcode.OP_EQUAL: op_equal,
    Opcode.OP_EQUALVERIFY: op_equalverify,
    Opcode.OP_CHECKSIG: op_checksig,
    Opcode.OP_HASH160: op_hash160,
    Opcode.OP_GREATERTHAN_TIMESTAMP: op_greaterthan_timestamp,
    Opcode.OP_CHECKMULTISIG: op_checkmultisig,
    Opcode.OP_DATA_STREQUAL: op_data_strequal,
    Opcode.OP_DATA_GREATERTHAN: op_data_greaterthan,
    Opcode.OP_DATA_MATCH_VALUE: op_data_match_value,
    Opcode.OP_CHECKDATASIG: op_checkdatasig,
    Opcode.OP_FIND_P2PKH: op_find_p2pkh,
}
