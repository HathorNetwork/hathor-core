"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""
import base64
import datetime
import hashlib
from abc import ABC, abstractmethod
from enum import IntEnum
from math import isfinite, log
from struct import error as StructError, pack
from typing import Any, ClassVar, Dict, List, Optional, Tuple, Type, Self, TypeAlias, Callable

from _hashlib import HASH

from hathorlib.conf import HathorSettings
from hathorlib.exceptions import InvalidOutputValue, WeightError
from hathorlib.scripts import P2PKH, DataScript, MultiSig, parse_address_script
from hathorlib.utils import int_to_bytes, unpack, unpack_len
from hathorlib.vertex_parser import VertexParser

settings = HathorSettings()

MAX_NONCE = 2**32

MAX_OUTPUT_VALUE = 2**63  # max value (inclusive) that is possible to encode: 9223372036854775808 ~= 9.22337e+18
_MAX_OUTPUT_VALUE_32 = 2**31 - 1  # max value (inclusive) before having to use 8 bytes: 2147483647 ~= 2.14748e+09

TX_HASH_SIZE = 32   # 256 bits, 32 bytes

# H = unsigned short (2 bytes), d = double(8), f = float(4), I = unsigned int (4),
# Q = unsigned long long int (64), B = unsigned char (1 byte)

# Signal bits (B), version (B), inputs len (B), and outputs len (B), token uids len (B).
_SIGHASH_ALL_FORMAT_STRING = '!BBBBB'

# Weight (d), timestamp (I), and parents len (B)
_GRAPH_FORMAT_STRING = '!dIB'

# The int value of one byte
_ONE_BYTE = 0xFF


Address: TypeAlias = bytes         # NewType('Address', bytes)
AddressB58: TypeAlias = str
Amount: TypeAlias = int            # NewType('Amount', int)
Timestamp: TypeAlias = int         # NewType('Timestamp', int)
TxOutputScript: TypeAlias = bytes  # NewType('TxOutputScript', bytes)
VertexId: TypeAlias = bytes        # NewType('VertexId', bytes)
TokenUid: TypeAlias = VertexId     # NewType('TokenUid', VertexId)
VerboseCallback = Optional[Callable[[str, Any], None]]


def sum_weights(w1: float, w2: float) -> float:
    return aux_calc_weight(w1, w2, 1)


def sub_weights(w1: float, w2: float) -> float:
    if w1 == w2:
        return 0
    return aux_calc_weight(w1, w2, -1)


def aux_calc_weight(w1: float, w2: float, multiplier: int) -> float:
    a = max(w1, w2)
    b = min(w1, w2)
    if b == 0.0:
        # Zero is a special acc_weight.
        # We could use float('-inf'), but it is not serializable.
        return a
    return a + log(1 + 2**(b - a) * multiplier, 2)


class TxVersion(IntEnum):
    """Versions are sequential for blocks and transactions"""

    REGULAR_BLOCK = 0
    REGULAR_TRANSACTION = 1
    TOKEN_CREATION_TRANSACTION = 2
    MERGE_MINED_BLOCK = 3
    NANO_CONTRACT = 4
    ON_CHAIN_BLUEPRINT = 6

    @classmethod
    def _missing_(cls, value: Any) -> None:
        assert isinstance(value, int), f"Value '{value}' must be an integer"
        assert value <= _ONE_BYTE, f'Value {hex(value)} must not be larger than one byte'

        raise ValueError(f'Invalid version: {value}')

    def get_cls(self) -> Type['GenericVertex']:
        from hathorlib import Block, TokenCreationTransaction, Transaction
        from hathorlib.nanocontracts.nanocontract import DeprecatedNanoContract
        from hathorlib.nanocontracts.on_chain_blueprint import OnChainBlueprint

        cls_map: Dict[TxVersion, Type[GenericVertex]] = {
            TxVersion.REGULAR_BLOCK: Block,
            TxVersion.REGULAR_TRANSACTION: Transaction,
            TxVersion.TOKEN_CREATION_TRANSACTION: TokenCreationTransaction,
            TxVersion.NANO_CONTRACT: DeprecatedNanoContract,
            TxVersion.ON_CHAIN_BLUEPRINT: OnChainBlueprint,
        }

        cls = cls_map.get(self)

        if cls is None:
            raise ValueError('Invalid version.')
        else:
            return cls


class GenericVertex(ABC):
    """Hathor base transaction"""

    __slots__ = (
        'name', 'version', 'signal_bits', 'weight', 'timestamp', 'nonce', 'inputs', 'outputs', 'parents', '_hash', 'headers'
    )

    # Even though nonce is serialized with different sizes for tx and blocks
    # the same size is used for hashes to enable mining algorithm compatibility
    SERIALIZATION_NONCE_SIZE: ClassVar[int]
    HASH_NONCE_SIZE = 16
    HEX_BASE = 16

    # Bits extracted from the first byte of the version field. They carry extra information that may be interpreted
    # differently by each subclass of GenericVertex.
    # Currently only the Block subclass uses it, carrying information about Feature Activation bits and also extra
    # bits reserved for future use, depending on the configuration.
    signal_bits: int

    def __init__(self) -> None:
        from hathorlib.headers import VertexBaseHeader
        self.nonce: int = 0
        self.timestamp: int = 0
        self.signal_bits: int = 0
        self.version: int = 0
        self.weight: float = 0
        self.inputs: List['TxInput'] = []
        self.outputs: List['TxOutput'] = []
        self.parents: List[bytes] = []
        self._hash: Optional[bytes] = None
        self.headers: list[VertexBaseHeader] = []
        self.name = None

    @property
    @abstractmethod
    def is_block(self) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def is_transaction(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_token_uid(self, index: int) -> TokenUid:
        raise NotImplementedError

    def is_nano_contract(self) -> bool:
        """Return True if this transaction is a nano contract or not."""
        return False

    def has_fees(self) -> bool:
        """Return True if this transaction has fees or not."""
        return False

    def _get_formatted_fields_dict(self, short: bool = True) -> Dict[str, str]:
        """ Used internally on __repr__ and __str__, returns a dict of `field_name: formatted_value`.
        """
        from collections import OrderedDict
        d = OrderedDict(
            name=self.name or '',
            nonce='%d' % (self.nonce or 0),
            timestamp='%s' % self.timestamp,
            version='%s' % int(self.version),
            weight='%f' % self.weight,
            hash=self.hash_hex,
        )
        if not short:
            d.update(
                inputs=repr(self.inputs),
                outputs=repr(self.outputs),
                parents=repr([x.hex() for x in self.parents]),
            )
        return d

    def __repr__(self) -> str:
        class_name = type(self).__name__
        return '%s(%s)' % (class_name, ', '.join('%s=%s' % i for i in self._get_formatted_fields_dict(False).items()))

    def __str__(self) -> str:
        class_name = type(self).__name__
        return '%s(%s)' % (class_name, ', '.join('%s=%s' % i for i in self._get_formatted_fields_dict().items()))

    def clone(self) -> Self:
        """Return exact copy without sharing memory, including metadata if loaded.

        :return: Transaction or Block copy
        """
        return self.create_from_struct(bytes(self))

    def get_fields_from_struct(self, struct_bytes: bytes, *, verbose: VerboseCallback = None) -> bytes:
        """ Gets all common fields for a Transaction and a Block from a buffer.

        :param struct_bytes: Bytes of a serialized transaction
        :type struct_bytes: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        buf = self.get_funds_fields_from_struct(struct_bytes, verbose=verbose)
        buf = self.get_graph_fields_from_struct(buf, verbose=verbose)
        return buf

    def get_header_from_bytes(self, buf: bytes) -> bytes:
        """Parse bytes and return the next header in buffer."""
        if len(self.headers) >= self.get_maximum_number_of_headers():
            raise ValueError('too many headers')

        header_type = buf[:1]
        header_class = VertexParser.get_header_parser(header_type)
        header, buf = header_class.deserialize(self, buf)
        self.headers.append(header)
        return buf

    def get_maximum_number_of_headers(self) -> int:
        """Return the maximum number of headers for this vertex."""
        return 2

    @classmethod
    @abstractmethod
    def create_from_struct(cls, struct_bytes: bytes) -> Self:
        """ Create a transaction from its bytes.

        :param struct_bytes: Bytes of a serialized transaction
        :type struct_bytes: bytes

        :return: A transaction or a block, depending on the class `cls`

        :raises ValueError: when the sequence of bytes is incorrect
        """
        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        """Two transactions are equal when their hash matches

        :raises NotImplement: when one of the transactions do not have a calculated hash
        """
        if not isinstance(other, GenericVertex):
            return NotImplemented
        if self._hash and other._hash:
            return self.hash == other.hash
        return False

    def __bytes__(self) -> bytes:
        """Returns a byte representation of the transaction

        :rtype: bytes
        """
        return self.get_struct()

    def __hash__(self) -> int:
        return hash(self.hash)

    @property
    def hash(self) -> VertexId:
        assert self._hash is not None, 'Vertex hash must be initialized.'
        return self._hash

    @hash.setter
    def hash(self, value: VertexId) -> None:
        self._hash = value

    @property
    def hash_hex(self) -> str:
        """Return the current stored hash in hex string format"""
        if self._hash is not None:
            return self.hash.hex()
        else:
            return ''

    @property
    def sum_outputs(self) -> int:
        """Sum of the value of the outputs"""
        return sum(output.value for output in self.outputs if not output.is_token_authority())

    def get_target(self, override_weight: Optional[float] = None) -> int:
        """Target to be achieved in the mining process"""
        if not isfinite(self.weight):
            raise WeightError
        return int(2**(256 - (override_weight or self.weight)) - 1)

    def get_time_from_now(self, now: Optional[Any] = None) -> str:
        """ Return a the time difference between now and the tx's timestamp

        :return: String in the format "0 days, 00:00:00"
        :rtype: str
        """
        if now is None:
            now = datetime.datetime.now()
        ts = datetime.datetime.fromtimestamp(self.timestamp)
        dt = now - ts
        seconds = dt.seconds
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        return '{} days, {:02d}:{:02d}:{:02d}'.format(dt.days, hours, minutes, seconds)

    @abstractmethod
    def get_funds_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        raise NotImplementedError

    def get_graph_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        """ Gets all common graph fields for a Transaction and a Block from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.weight, self.timestamp, parents_len), buf = unpack(_GRAPH_FORMAT_STRING, buf)
        if verbose:
            verbose('weigth', self.weight)
            verbose('timestamp', self.timestamp)
            verbose('parents_len', parents_len)

        for _ in range(parents_len):
            parent, buf = unpack_len(TX_HASH_SIZE, buf)  # 256bits
            self.parents.append(parent)
            if verbose:
                verbose('parent', parent.hex())

        return buf

    @abstractmethod
    def get_funds_struct(self) -> bytes:
        raise NotImplementedError

    def get_graph_struct(self) -> bytes:
        """Return the graph data serialization of the transaction, without including the nonce field

        :return: graph data serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = pack(_GRAPH_FORMAT_STRING, self.weight, self.timestamp, len(self.parents))
        for parent in self.parents:
            struct_bytes += parent
        return struct_bytes

    def get_headers_struct(self) -> bytes:
        """Return the serialization of the headers only."""
        return b''.join(h.serialize() for h in self.headers)

    def get_struct_without_nonce(self) -> bytes:
        """Return a partial serialization of the transaction, without including the nonce field

        :return: Partial serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = self.get_funds_struct()
        struct_bytes += self.get_graph_struct()
        return struct_bytes

    def get_struct_nonce(self) -> bytes:
        """Return a partial serialization of the transaction's proof-of-work, which is usually the nonce field

        :return: Partial serialization of the transaction's proof-of-work
        :rtype: bytes
        """
        assert self.SERIALIZATION_NONCE_SIZE is not None
        struct_bytes = int_to_bytes(self.nonce, self.SERIALIZATION_NONCE_SIZE)
        return struct_bytes

    def get_struct(self) -> bytes:
        """Return the complete serialization of the transaction

        :rtype: bytes
        """
        struct_bytes = self.get_struct_without_nonce()
        struct_bytes += self.get_struct_nonce()
        struct_bytes += self.get_headers_struct()
        return struct_bytes

    def verify_pow(self, override_weight: Optional[float] = None) -> bool:
        """Verify proof-of-work

        :raises PowError: when the hash is equal or greater than the target
        """
        assert self.hash is not None
        numeric_hash = int(self.hash.hex(), self.HEX_BASE)
        minimum_target = self.get_target(override_weight)
        if numeric_hash >= minimum_target:
            return False
        return True

    def get_funds_hash(self) -> bytes:
        """Return the sha256 of the funds part of the transaction

        :return: the hash of the funds data
        :rtype: bytes
        """
        funds_hash = hashlib.sha256()
        funds_hash.update(self.get_funds_struct())
        return funds_hash.digest()

    def get_graph_and_headers_hash(self) -> bytes:
        """Return the sha256 of the graph part of the transaction + its headers

        :return: the hash of the graph and headers data
        :rtype: bytes
        """
        h = hashlib.sha256()
        h.update(self.get_graph_struct())
        h.update(self.get_headers_struct())
        return h.digest()

    def get_mining_header_without_nonce(self) -> bytes:
        """Return the transaction header without the nonce

        :return: transaction header without the nonce
        :rtype: bytes
        """
        data = self.get_funds_hash() + self.get_graph_and_headers_hash()
        assert len(data) == 64, 'the mining data should have a fixed size of 64 bytes'
        return data

    def calculate_hash1(self) -> HASH:
        """Return the sha256 of the transaction without including the `nonce`

        :return: A partial hash of the transaction
        :rtype: :py:class:`_hashlib.HASH`
        """
        calculate_hash1 = hashlib.sha256()
        calculate_hash1.update(self.get_mining_header_without_nonce())
        return calculate_hash1

    def calculate_hash2(self, part1: HASH) -> bytes:
        """Return the hash of the transaction, starting from a partial hash

        The hash of the transactions is the `sha256(sha256(bytes(tx))`.

        :param part1: A partial hash of the transaction, usually from `calculate_hash1`
        :type part1: :py:class:`_hashlib.HASH`

        :return: The transaction hash
        :rtype: bytes
        """
        part1.update(self.nonce.to_bytes(self.HASH_NONCE_SIZE, byteorder='big', signed=False))
        # SHA256D gets the hash in littlean format. Reverse the bytes to get the big-endian representation.
        return hashlib.sha256(part1.digest()).digest()[::-1]

    def calculate_hash(self) -> bytes:
        """Return the full hash of the transaction

        It is the same as calling `self.calculate_hash2(self.calculate_hash1())`.

        :return: The hash transaction
        :rtype: bytes
        """
        part1 = self.calculate_hash1()
        return self.calculate_hash2(part1)

    def is_nft_creation_standard(self) -> bool:
        """Returns True if it's an NFT creation transaction"""
        return False

    def is_standard(self, std_max_output_script_size: int = settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE,
                    only_standard_script_type: bool = True,
                    max_number_of_data_script_outputs: int = settings.MAX_DATA_SCRIPT_OUTPUTS) -> bool:
        """ Return True is the transaction is standard
        """
        # TODO in the future we should have a way to know which standard validation failed
        # we could have an array of errors from args that we append an error object
        # or a bool parameter "raise_on_non_standard", which will raise an error if it's non standard

        # First we check if t's an NFT standard
        # We could remove this because now that we are adding support
        # for some data script outputs in a transaction, this would
        # also be considered a standard but if we change our minds
        # about the data scripts in the future we would need to remember
        # to add NFT support back, so I'm just keeping this here
        if self.is_nft_creation_standard():
            return True

        # We've discussed to allow any number of Data Script outputs but we decided to
        # add some restrictions first. Because of that we are not making Data Script a
        # standard script and we are handling it manually
        number_of_data_script_outputs = 0
        for output in self.outputs:
            if not output.is_standard_script(std_max_output_script_size, only_standard_script_type):
                # If not standard then we check if it's a data script with valid size
                if output.is_script_size_valid(std_max_output_script_size) and output.is_data_script():
                    # Then we check if it already reached the maximum number of data script outputs
                    if number_of_data_script_outputs == max_number_of_data_script_outputs:
                        return False
                    else:
                        number_of_data_script_outputs += 1
                        continue

                return False

        return True

    def to_json(self, decode_script: bool = False) -> dict[str, Any]:
        """ Creates a json serializable dict object from self
        """
        data: dict[str, Any] = {}
        data['hash'] = self.hash_hex or None
        data['nonce'] = self.nonce
        data['timestamp'] = self.timestamp
        data['version'] = int(self.version)
        data['weight'] = self.weight
        data['signal_bits'] = self.signal_bits

        data['parents'] = []
        for parent in self.parents:
            data['parents'].append(parent.hex())

        data['inputs'] = []
        for tx_input in self.inputs:
            data_input: dict[str, Any] = {}
            data_input['tx_id'] = tx_input.tx_id.hex()
            data_input['index'] = tx_input.index
            data_input['data'] = base64.b64encode(tx_input.data).decode('utf-8')
            data['inputs'].append(data_input)

        data['outputs'] = []
        for output in self.outputs:
            data['outputs'].append(output.to_json(decode_script=decode_script))

        return data


class TxInput:
    _tx: GenericVertex  # XXX: used for caching on hathor.transaction.Transaction.get_spent_tx

    def __init__(self, tx_id: bytes, index: int, data: bytes) -> None:
        """
            tx_id: hash of the transaction that contains the output of this input
            index: index of the output you are spending from transaction tx_id (1 byte)
            data: data to solve output script
        """
        assert isinstance(tx_id, bytes), 'Value is %s, type %s' % (str(tx_id), type(tx_id))
        assert isinstance(index, int), 'Value is %s, type %s' % (str(index), type(index))
        assert isinstance(data, bytes), 'Value is %s, type %s' % (str(data), type(data))

        self.tx_id = tx_id  # bytes
        self.index = index  # int
        self.data = data  # bytes

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return 'TxInput(tx_id=%s, index=%s)' % (self.tx_id.hex(), self.index)

    def __bytes__(self) -> bytes:
        """Returns a byte representation of the input

        :rtype: bytes
        """
        ret = b''
        ret += self.tx_id
        ret += int_to_bytes(self.index, 1)
        ret += int_to_bytes(len(self.data), 2)  # data length
        ret += self.data
        return ret

    def get_sighash_bytes(self) -> bytes:
        """Return a serialization of the input for the sighash

        :return: Serialization of the input
        :rtype: bytes
        """
        ret = bytearray()
        ret += self.tx_id
        ret += int_to_bytes(self.index, 1)
        ret += int_to_bytes(0, 2)
        return bytes(ret)

    @classmethod
    def create_from_bytes(cls, buf: bytes, *, verbose: VerboseCallback = None) -> Tuple['TxInput', bytes]:
        """ Creates a TxInput from a serialized input. Returns the input
        and remaining bytes
        """
        input_tx_id, buf = unpack_len(TX_HASH_SIZE, buf)
        if verbose:
            verbose('txin_tx_id', input_tx_id.hex())
        (input_index, data_len), buf = unpack('!BH', buf)
        if verbose:
            verbose('txin_index', input_index)
            verbose('txin_data_len', data_len)
        input_data, buf = unpack_len(data_len, buf)
        if verbose:
            verbose('txin_data', input_data.hex())
        txin = cls(input_tx_id, input_index, input_data)
        return txin, buf

    @classmethod
    def create_from_dict(cls, data: dict) -> 'TxInput':
        """ Creates a TxInput from a human readable dict."""
        return cls(
            bytes.fromhex(data['tx_id']),
            int(data['index']),
            base64.b64decode(data['data']) if data.get('data') else b'',
        )

    def to_human_readable(self) -> Dict[str, Any]:
        """Returns dict of Input information, ready to be serialized

        :rtype: Dict
        """
        return {
            'tx_id': self.tx_id.hex(),  # string
            'index': self.index,  # int
            'data':
                base64.b64encode(self.data).decode('utf-8')  # string
        }


class TxOutput:

    # first bit in the index byte indicates whether it's an authority output
    TOKEN_INDEX_MASK = 0b01111111
    TOKEN_AUTHORITY_MASK = 0b10000000

    # last bit is mint authority
    TOKEN_MINT_MASK = 0b00000001
    # second to last bit is melt authority
    TOKEN_MELT_MASK = 0b00000010

    ALL_AUTHORITIES = TOKEN_MINT_MASK | TOKEN_MELT_MASK

    # standard types for output script
    STANDARD_SCRIPT_TYPES = (P2PKH, MultiSig)

    def __init__(self, value: int, script: bytes, token_data: int = 0) -> None:
        """
            value: amount spent (4 bytes)
            script: script in bytes
            token_data: index of the token uid in the uid list
        """
        assert isinstance(value, int), 'value is %s, type %s' % (str(value), type(value))
        assert isinstance(script, bytes), 'script is %s, type %s' % (str(script), type(script))
        assert isinstance(token_data, int), 'token_data is %s, type %s' % (str(token_data), type(token_data))
        if value <= 0 or value > MAX_OUTPUT_VALUE:
            raise InvalidOutputValue

        self.value = value  # int
        self.script = script  # bytes
        self.token_data = token_data  # int

    def __eq__(self, other):
        return (
            self.value == other.value and
            self.script == other.script and
            self.token_data == other.token_data
        )

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        cls_name = type(self).__name__
        value_str = hex(self.value) if self.is_token_authority() else str(self.value)
        if self.token_data:
            return f'{cls_name}(token_data={bin(self.token_data)}, value={value_str}, script={self.script.hex()})'
        else:
            return f'{cls_name}(value={value_str}, script={self.script.hex()})'

    def __bytes__(self) -> bytes:
        """Returns a byte representation of the output

        :rtype: bytes
        """
        ret = b''
        ret += output_value_to_bytes(self.value)
        ret += int_to_bytes(self.token_data, 1)
        ret += int_to_bytes(len(self.script), 2)    # script length
        ret += self.script
        return ret

    @classmethod
    def create_from_bytes(cls, buf: bytes, *, verbose: VerboseCallback = None) -> tuple['TxOutput', bytes]:
        """ Creates a TxOutput from a serialized output. Returns the output
        and remaining bytes
        """
        value, buf = bytes_to_output_value(buf)
        if verbose:
            verbose('txout_value', value)
        (token_data, script_len), buf = unpack('!BH', buf)
        if verbose:
            verbose('txout_token_data', token_data)
            verbose('txout_script_len', script_len)
        script, buf = unpack_len(script_len, buf)
        if verbose:
            verbose('txout_script', script.hex())
        txout = cls(value, script, token_data)
        return txout, buf

    def get_token_index(self) -> int:
        """The token uid index in the list"""
        return self.token_data & self.TOKEN_INDEX_MASK

    def is_token_authority(self) -> bool:
        """Whether this is a token authority output"""
        return (self.token_data & self.TOKEN_AUTHORITY_MASK) > 0

    def can_mint_token(self) -> bool:
        """Whether this utxo can mint tokens"""
        return self.is_token_authority() and ((self.value & self.TOKEN_MINT_MASK) > 0)

    def can_melt_token(self) -> bool:
        """Whether this utxo can melt tokens"""
        return self.is_token_authority() and ((self.value & self.TOKEN_MELT_MASK) > 0)

    def to_human_readable(self) -> Dict[str, Any]:
        """Checks what kind of script this is and returns it in human readable form
        """
        from hathorlib.scripts import NanoContractMatchValues, parse_address_script

        script_type = parse_address_script(self.script)
        if script_type:
            ret = script_type.to_human_readable()
            ret['value'] = self.value
            ret['token_data'] = self.token_data
            return ret

        nano_contract = NanoContractMatchValues.parse_script(self.script)
        if nano_contract:
            return nano_contract.to_human_readable()

        return {}

    def to_json(self, *, decode_script: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        data['value'] = self.value
        data['token_data'] = self.token_data
        data['script'] = base64.b64encode(self.script).decode('utf-8')
        if decode_script:
            data['decoded'] = self.to_human_readable()
        return data

    def is_script_size_valid(self, max_output_script_size: int = settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE) -> bool:
        """Return True if output script size is valid"""
        if len(self.script) > max_output_script_size:
            return False

        return True

    def is_data_script(self) -> bool:
        """Return True if output script is a DataScript"""
        return DataScript.parse_script(self.script) is not None

    def is_standard_script(self, std_max_output_script_size: int = settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE,
                           only_standard_script_type: bool = True) -> bool:
        """Return True if this output has a standard script."""
        # First check: script size limit
        if not self.is_script_size_valid(std_max_output_script_size):
            return False

        # Second check: output script type
        # if we allow different script types, then it's ok
        # otherwise we check if it's one of the standard types
        if only_standard_script_type:
            parsed_output = parse_address_script(self.script)
            if parsed_output is None or not isinstance(parsed_output, self.STANDARD_SCRIPT_TYPES):
                return False

        return True


def bytes_to_output_value(buf: bytes) -> Tuple[int, bytes]:
    (value_high_byte,), _ = unpack('!b', buf)
    if value_high_byte < 0:
        output_struct = '!q'
        value_sign = -1
    else:
        output_struct = '!i'
        value_sign = 1
    try:
        (signed_value,), buf = unpack(output_struct, buf)
    except StructError as e:
        raise InvalidOutputValue('Invalid byte struct for output') from e
    value = signed_value * value_sign
    assert value >= 0
    if value < _MAX_OUTPUT_VALUE_32 and value_high_byte < 0:
        raise ValueError('Value fits in 4 bytes but is using 8 bytes')
    return value, buf


def output_value_to_bytes(number: int) -> bytes:
    if number <= 0:
        raise InvalidOutputValue('Invalid value for output')

    if number > _MAX_OUTPUT_VALUE_32:
        return (-number).to_bytes(8, byteorder='big', signed=True)
    else:
        return number.to_bytes(4, byteorder='big', signed=True)  # `signed` makes no difference, but oh well


def tx_or_block_from_bytes(data: bytes) -> GenericVertex:
    """ Creates the correct tx subclass from a sequence of bytes
    """
    # version field takes up the second byte only
    version = data[1]
    try:
        tx_version = TxVersion(version)
        cls = tx_version.get_cls()
        return cls.create_from_struct(data)
    except ValueError:
        raise StructError('Invalid bytes to create transaction subclass.')
