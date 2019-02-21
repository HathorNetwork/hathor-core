# encoding: utf-8

import base64
import datetime
import hashlib
import time
from abc import ABC, abstractclassmethod, abstractmethod
from enum import Enum
from math import inf, log
from struct import pack
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

from _hashlib import HASH

from hathor import protos
from hathor.constants import HATHOR_TOKEN_UID, MAX_DISTANCE_BETWEEN_BLOCKS, TX_NONCE_BYTES as NONCE_BYTES
from hathor.transaction.exceptions import (
    DuplicatedParents,
    IncorrectParents,
    ParentDoesNotExist,
    PowError,
    TimestampError,
    TxValidationError,
)
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.transaction.util import int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

MAX_NONCE = 2**32
MAX_NUM_INPUTS = MAX_NUM_OUTPUTS = 256

MAX_OUTPUT_VALUE = 2**63  # max value (inclusive) that is possible to encode: 9223372036854775808 ~= 9.22337e+18
_MAX_OUTPUT_VALUE_32 = 2**31 - 1  # max value (inclusive) before having to use 8 bytes: 2147483647 ~= 2.14748e+09

_INPUT_SIZE_BYTES = 32  # 256 bits

# Version (H), weight (d), timestamp (I), inputs len (B), outputs len (B) and
# parents len (B), token uids len (B).
# H = unsigned short (2 bytes), d = double(8), f = float(4), I = unsigned int (4),
# Q = unsigned long long int (64), B = unsigned char (1 byte)
_TRANSACTION_FORMAT_STRING = '!HdIBBBB'  # Update code below if this changes.

# Version (H), inputs len (B), and outputs len (B), token uids len (B).
# H = unsigned short (2 bytes)
_SIGHASH_ALL_FORMAT_STRING = '!HBBB'

# tx should have 2 parents, both other transactions
_TX_PARENTS_TXS = 2
_TX_PARENTS_BLOCKS = 0

# blocks have 3 parents, 2 txs and 1 block
_BLOCK_PARENTS_TXS = 2
_BLOCK_PARENTS_BLOCKS = 1


def sum_weights(w1: float, w2: float) -> float:
    return aux_calc_weight(w1, w2, 1)


def sub_weights(w1: float, w2: float) -> float:
    if w1 == w2:
        return 0
    return aux_calc_weight(w1, w2, -1)


def aux_calc_weight(w1: float, w2: float, multiplier: int) -> float:
    a = max(w1, w2)
    b = min(w1, w2)
    if b == 0:
        # Zero is a special acc_weight.
        # We could use float('-inf'), but it is not serializable.
        return a
    return a + log(1 + 2**(b - a) * multiplier, 2)


class BaseTransaction(ABC):
    """Hathor base transaction"""

    class GenesisDagConnectivity(Enum):
        UNKNOWN = -1
        DISCONNECTED = 0
        CONNECTED = 1

    def __init__(self, nonce: int = 0, timestamp: Optional[int] = None, version: int = 1, weight: float = 0,
                 inputs: Optional[List['TxInput']] = None, outputs: Optional[List['TxOutput']] = None,
                 parents: List[bytes] = None, tokens: Optional[List[bytes]] = None, hash: Optional[bytes] = None,
                 storage: Optional['TransactionStorage'] = None, is_block: bool = True) -> None:
        """
            Nonce: nonce used for the proof-of-work
            Timestamp: moment of creation
            Version: version when it was created
            Weight: different for transactions and blocks
            Outputs: all outputs that are being created
            Parents: transactions you are confirming (2 transactions and 1 block - in case of a block only)
            Tokens: list of token uids in this transaction
        """
        self.nonce = nonce
        self.timestamp = timestamp or int(time.time())
        self.version = version
        self.weight = weight
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.parents = parents or []
        self.tokens = tokens or []
        self.storage = storage
        self.hash = hash  # Stored as bytes.
        self.is_block = is_block

        # Locally we keep track of whether this tx is connected back to a genesis tx.
        self.genesis_dag_connectivity = self.GenesisDagConnectivity.UNKNOWN

    def __repr__(self):
        class_name = type(self).__name__
        return ('%s(nonce=%d, timestamp=%s, version=%s, weight=%f, inputs=%s, outputs=%s, parents=%s, '
                'hash=%s, storage=%s)' %
                (class_name, self.nonce, self.timestamp, self.version, self.weight,
                 repr(self.inputs), repr(self.outputs), repr(self.parents), self.hash_hex, repr(self.storage)))

    def __str__(self):
        class_name = 'Block' if self.is_block else 'Transaction'
        return ('%s(nonce=%d, timestamp=%s, version=%s, weight=%f, hash=%s)' % (class_name, self.nonce, self.timestamp,
                self.version, self.weight, self.hash_hex))

    def get_fields_from_struct(self, struct_bytes: bytes) -> bytes:
        """ Gets all common fields for a Transaction and a Block from a buffer.

        :param struct_bytes: Bytes of a serialized transaction
        :type struct_bytes: bytes

        :return: A buffer containing the remaining struct bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        buf = struct_bytes

        (self.version, self.weight, self.timestamp, inputs_len, outputs_len, parents_len,
         tokens_len), buf = (unpack(_TRANSACTION_FORMAT_STRING, buf))

        for _ in range(parents_len):
            parent, buf = unpack_len(32, buf)  # 256bits
            self.parents.append(parent)

        for _ in range(tokens_len):
            token_uid, buf = unpack_len(32, buf)  # 256bits
            self.tokens.append(token_uid)

        for _ in range(inputs_len):
            input_tx_id, buf = unpack_len(_INPUT_SIZE_BYTES, buf)  # 256bits
            (input_index, data_len), buf = unpack('!BH', buf)
            input_data, buf = unpack_len(data_len, buf)
            txin = TxInput(input_tx_id, input_index, input_data)
            self.inputs.append(txin)

        for _ in range(outputs_len):
            value, buf = bytes_to_output_value(buf)
            (token_data, script_len), buf = unpack('!BH', buf)
            script, buf = unpack_len(script_len, buf)
            txout = TxOutput(value, script, token_data)
            self.outputs.append(txout)

        return buf

    @classmethod
    @abstractmethod
    def create_from_struct(cls, struct_bytes: bytes,
                           storage: Optional['TransactionStorage'] = None) -> 'BaseTransaction':
        """ Create a transaction from its bytes.

        :param struct_bytes: Bytes of a serialized transaction
        :type struct_bytes: bytes

        :return: A transaction or a block, depending on the class `cls`

        :raises ValueError: when the sequence of bytes is incorrect
        """
        raise NotImplementedError

    @abstractclassmethod
    def create_from_proto(cls, tx_proto: protos.BaseTransaction, storage=None):
        """ Create a Transaction from a protobuf Transaction object.

        :param transaction_proto: Protobuf transaction object
        :type transaction_proto: :py:class:`hathor.protos.Transaction`

        :return: A transaction or a block, depending on the class `cls`
        :rtype :py:class:`hathor.transaction.BaseTransaction`
        """
        raise NotImplementedError

    def __eq__(self, other):
        """Two transactions are equal when their hash matches

        :raises NotImplement: when one of the transactions do not have a calculated hash
        """
        if self.hash and other.hash:
            return self.hash == other.hash
        return False

    def __bytes__(self):
        """Returns a byte representation of the transaction

        :rtype: bytes
        """
        return self.get_struct()

    def __hash__(self):
        assert self.hash is not None
        return hash(self.hash)

    @property
    def hash_hex(self) -> str:
        """Return the current stored hash in hex string format"""
        assert self.hash is not None
        return self.hash.hex()

    @property
    def sum_outputs(self) -> int:
        """Sum of the value of the outputs"""
        return sum([output.value for output in self.outputs])

    def get_target(self) -> float:
        """Target to be achieved in the mining process"""
        return 2**(256 - self.weight) - 1

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

    def get_parents(self) -> Iterator['BaseTransaction']:
        """Return an iterator of the parents

        :return: An iterator of the parents
        :rtype: Iter[BaseTransaction]
        """
        for parent_hash in self.parents:
            assert self.storage is not None
            yield self.storage.get_transaction(parent_hash)

    @property
    def is_genesis(self) -> bool:
        """ Check whether this transaction is a genesis transaction

        :rtype: bool
        """
        if self.storage:
            genesis = self.storage.get_genesis(self.hash)
            if genesis:
                return True
            else:
                return False
        else:
            from hathor.transaction.genesis import genesis_transactions
            for genesis in genesis_transactions(self.storage):
                if self == genesis:
                    return True
            return False

    @abstractclassmethod
    def update_voided_info(self) -> None:
        """ This method is called when a new transaction or block arrives and is added to the DAG.
        It must check whether the transaction or block is voided or not. It has different implementation
        in each case.
        """
        raise NotImplementedError

    def get_sighash_all(self, clear_input_data: bool = True) -> bytes:
        """Return a  serialization of the inputs and outputs, without including any other field

        :return: Serialization of the inputs and outputs
        :rtype: bytes
        """
        struct_bytes = pack(_SIGHASH_ALL_FORMAT_STRING, self.version, len(self.inputs), len(self.outputs),
                            len(self.tokens))

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for input_tx in self.inputs:
            struct_bytes += input_tx.tx_id
            struct_bytes += bytes([input_tx.index])  # 1 byte

            # data length
            if not clear_input_data:
                struct_bytes += int_to_bytes(len(input_tx.data), 2)
                struct_bytes += input_tx.data
            else:
                struct_bytes += int_to_bytes(0, 2)

        for output_tx in self.outputs:
            struct_bytes += output_value_to_bytes(output_tx.value)

            # token index
            struct_bytes += int_to_bytes(output_tx.token_data, 1)

            # script length
            struct_bytes += int_to_bytes(len(output_tx.script), 2)
            struct_bytes += output_tx.script

        return struct_bytes

    def get_struct_without_nonce(self) -> bytes:
        """Return a partial serialization of the transaction, without including the nonce field

        :return: Partial serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = pack(_TRANSACTION_FORMAT_STRING, self.version, self.weight, self.timestamp,
                            len(self.inputs), len(self.outputs), len(self.parents), len(self.tokens))

        for parent in self.parents:
            struct_bytes += parent

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for input_tx in self.inputs:
            struct_bytes += input_tx.tx_id
            struct_bytes += bytes([input_tx.index])  # 1 byte

            # data length
            struct_bytes += int_to_bytes(len(input_tx.data), 2)
            struct_bytes += input_tx.data

        for output_tx in self.outputs:
            struct_bytes += output_value_to_bytes(output_tx.value)

            # token index
            struct_bytes += int_to_bytes(output_tx.token_data, 1)

            # script length
            struct_bytes += int_to_bytes(len(output_tx.script), 2)
            struct_bytes += output_tx.script

        return struct_bytes

    def get_struct(self) -> bytes:
        """Return the complete serialization of the transaction

        :rtype: bytes
        """
        struct_bytes = self.get_struct_without_nonce()
        struct_bytes += int_to_bytes(self.nonce, NONCE_BYTES)
        return struct_bytes

    def verify(self):
        raise NotImplementedError

    def verify_parents(self) -> None:
        """All parents must exist and their timestamps must be smaller than ours.

        Also, txs should have 2 other txs as parents, while blocks should have 2 txs + 1 block.

        Parents must be ordered with blocks first, followed by transactions.

        :raises TimestampError: when our timestamp is less or equal than our parent's timestamp
        :raises ParentDoesNotExist: when at least one of our parents does not exist
        :raises IncorrectParents: when tx does not confirm the correct number/type of parent txs
        """
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        assert self.hash is not None
        assert self.storage is not None

        # check if parents are duplicated
        parents_set = set(self.parents)
        if len(self.parents) > len(parents_set):
            raise DuplicatedParents('Tx has duplicated parents: {}', [tx_hash.hex() for tx_hash in self.parents])

        my_parents_txs = 0      # number of tx parents
        my_parents_blocks = 0   # number of block parents
        min_timestamp = None

        for parent_hash in self.parents:
            try:
                parent = self.storage.get_transaction(parent_hash)
                if self.timestamp <= parent.timestamp:
                    raise TimestampError('tx={} timestamp={}, parent={} timestamp={}'.format(
                        self.hash.hex(),
                        self.timestamp,
                        parent.hash.hex(),
                        parent.timestamp,
                    ))

                if parent.is_block:
                    if self.is_block and not parent.is_genesis:
                        if self.timestamp - parent.timestamp > MAX_DISTANCE_BETWEEN_BLOCKS:
                            raise TimestampError('Distance between blocks is too big'
                                                 ' ({} seconds)'.format(self.timestamp - parent.timestamp))
                    if my_parents_txs > 0:
                        raise IncorrectParents('Parents which are blocks must come before transactions')
                    for pi_hash in parent.parents:
                        pi = self.storage.get_transaction(parent_hash)
                        if not pi.is_block:
                            min_timestamp = (
                                min(min_timestamp, pi.timestamp) if min_timestamp is not None
                                else pi.timestamp
                            )
                    my_parents_blocks += 1
                else:
                    if min_timestamp and parent.timestamp < min_timestamp:
                        raise TimestampError('tx={} timestamp={}, parent={} timestamp={}, min_timestamp={}'.format(
                            self.hash.hex(),
                            self.timestamp,
                            parent.hash.hex(),
                            parent.timestamp,
                            min_timestamp
                        ))
                    my_parents_txs += 1
            except TransactionDoesNotExist:
                raise ParentDoesNotExist('tx={} parent={}'.format(self.hash.hex(), parent_hash.hex()))

        # check for correct number of parents
        if self.is_block:
            parents_txs = _BLOCK_PARENTS_TXS
            parents_blocks = _BLOCK_PARENTS_BLOCKS
        else:
            parents_txs = _TX_PARENTS_TXS
            parents_blocks = _TX_PARENTS_BLOCKS
        if my_parents_blocks != parents_blocks:
            raise IncorrectParents('wrong number of parents (block type): {}, expecting {}'.format(
                my_parents_blocks, parents_blocks))
        if my_parents_txs != parents_txs:
            raise IncorrectParents('wrong number of parents (tx type): {}, expecting {}'.format(
                my_parents_txs, parents_txs))

    def verify_pow(self) -> None:
        """Verify proof-of-work and that the weight is correct

        :raises PowError: when the hash is equal or greater than the target
        """
        assert self.hash is not None
        if int(self.hash.hex(), 16) >= self.get_target():
            raise PowError('Transaction has invalid data')

    def resolve(self) -> bool:
        """Run a CPU mining looking for the nonce that solves the proof-of-work

        The `self.weight` must be set before calling this method.

        :return: True if a solution was found
        :rtype: bool
        """
        hash_bytes = self.start_mining()

        if hash_bytes:
            self.hash = hash_bytes
            return True
        else:
            return False

    def calculate_hash1(self) -> HASH:
        """Return the sha256 of the transaction without including the `nonce`

        :return: A partial hash of the transaction
        :rtype: :py:class:`_hashlib.HASH`
        """
        calculate_hash1 = hashlib.sha256()
        calculate_hash1.update(self.get_struct_without_nonce())
        return calculate_hash1

    def calculate_hash2(self, part1: HASH) -> bytes:
        """Return the hash of the transaction, starting from a partial hash

        The hash of the transactions is the `sha256(sha256(bytes(tx))`.

        :param part1: A partial hash of the transaction, usually from `calculate_hash1`
        :type part1: :py:class:`_hashlib.HASH`

        :return: The transaction hash
        :rtype: bytes
        """
        part1.update(self.nonce.to_bytes(NONCE_BYTES, byteorder='big', signed=False))
        return hashlib.sha256(part1.digest()).digest()

    def calculate_hash(self) -> bytes:
        """Return the full hash of the transaction

        It is the same as calling `self.calculate_hash2(self.calculate_hash1())`.

        :return: The hash transaction
        :rtype: bytes
        """
        part1 = self.calculate_hash1()
        return self.calculate_hash2(part1)

    def update_hash(self) -> None:
        """ Update the hash of the transaction.
        """
        self.hash = self.calculate_hash()

    def start_mining(self, start: int = 0, end: int = MAX_NONCE, sleep_seconds: float = 0.0) -> Optional[bytes]:
        """Starts mining until it solves the problem, i.e., finds the nonce that satisfies the conditions

        :param start: beginning of the search interval
        :param end: end of the search interval
        :param sleep_seconds: the number of seconds it will sleep after each attempt
        :return The hash of the solved PoW or None when it is not found
        """
        pow_part1 = self.calculate_hash1()
        target = self.get_target()
        self.nonce = start
        last_time = time.time()
        while self.nonce < end:
            now = time.time()
            if now - last_time > 2:
                self.timestamp = int(now)
                pow_part1 = self.calculate_hash1()
                last_time = now
                self.nonce = start

            result = self.calculate_hash2(pow_part1.copy())
            if int(result.hex(), 16) < target:
                return result
            self.nonce += 1
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
        return None

    def get_metadata(self, *, force_reload: bool = False, use_storage: bool = True) -> TransactionMetadata:
        """Return this tx's metadata.

        It first looks in our cache (tx._metadata) and then tries the tx storage. If it doesn't
        exist, returns a new TransactionMetadata object.

        :param force_reload: don't load the cached metadata
        :type force_reload: bool

        :param use_storage: use self.storage.get_metadata if no metadata in cache
        :type use_storage: bool

        :rtype: :py:class:`hathor.transaction.TransactionMetadata`
        """
        if force_reload:
            metadata = None
        else:
            metadata = getattr(self, '_metadata', None)
        if not metadata and use_storage and self.storage:
            metadata = self.storage.get_metadata(self.hash)
            self._metadata = metadata
        if not metadata:
            metadata = TransactionMetadata(hash=self.hash, accumulated_weight=self.weight)
            self._metadata = metadata
        return metadata

    def reset_metadata(self) -> None:
        """ Reset transaction's metadata. It is used when a node is initializing and
        recalculating all metadata.
        """
        assert self.storage is not None
        self._metadata = TransactionMetadata(hash=self.hash, accumulated_weight=self.weight)
        self.storage.save_transaction(self, only_metadata=True)

    def update_accumulated_weight(self, *, stop_value: float = inf, save_file: bool = True) -> TransactionMetadata:
        """Calculates the tx's accumulated weight and update its metadata.

        It starts at the current transaction and does a BFS to the tips. In the
        end, updates the accumulated weight on metadata

        It stops calculating the accumulated weight when the value passes the `stop_value`.
        This may be used when the accumulated weight is being calculated to be compared to another value.
        In this case, we may stop calculating when we are already higher than `stop_value`.

        :param: stop_value: Threshold to stop calculating the accumulated weight.

        :return: transaction metadata
        :rtype: :py:class:`hathor.transaction.TransactionMetadata`
        """
        assert self.storage is not None

        metadata = self.get_metadata()
        if metadata.accumulated_weight > stop_value:
            return metadata

        accumulated_weight = self.weight

        # TODO We can walk by the blocks first, because they have higher weight and this may
        # reduce the number of visits in the BFS. One possibility is to use the tx's weight as the weight
        # of the edge and run a Djikstra.

        # TODO Another optimization is that, when we calculate the acc weight of a transaction, we
        # also partially calculate the acc weight of its descendants. If it were a DFS, when returning
        # to a vertex, the acc weight calculated would be <= the real acc weight. So, we might store it
        # as a pre-calculated value. Then, during the next DFS, if `cur + tx.acc_weight > stop_value`,
        # we might stop and avoid some visits. Question: how would we do it in the BFS?

        from hathor.transaction.storage.traversal import BFSWalk
        bfs_walk = BFSWalk(self.storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        for tx in bfs_walk.run(self, skip_root=True):
            accumulated_weight = sum_weights(accumulated_weight, tx.weight)
            if accumulated_weight > stop_value:
                break

        metadata.accumulated_weight = accumulated_weight
        if save_file:
            self.storage.save_transaction(self, only_metadata=True)

        return metadata

    def update_parents(self) -> None:
        """Update the tx's parents to add the current tx as their child.

        :rtype None
        """
        assert self.hash is not None
        assert self.storage is not None

        for parent in self.get_parents():
            metadata = parent.get_metadata()
            metadata.children.add(self.hash)
            self.storage.save_transaction(parent, only_metadata=True)

    def update_timestamp(self, now):
        """Update this tx's timestamp

        :param now: the current timestamp, in seconds
        :type now: int

        :rtype: None
        """
        assert self.storage is not None
        max_ts_spent_tx = max(self.get_spent_tx(txin).timestamp for txin in self.inputs)
        max_ts_parent = max(parent.timestamp for parent in self.get_parents())
        self.timestamp = max(max_ts_spent_tx + 1, max_ts_parent + 1, now)

    def to_json(self, decode_script: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        data['hash'] = self.hash and self.hash.hex()
        data['nonce'] = self.nonce
        data['timestamp'] = self.timestamp
        data['version'] = self.version
        data['weight'] = self.weight

        data['parents'] = []
        for parent in self.parents:
            data['parents'].append(parent.hex())

        data['inputs'] = []
        # Blocks don't have inputs
        # TODO(epnichols): Refactor so that blocks/transactions know how to serialize themselves? Then we could do
        #                  something like data['inputs'] = tx.serialize_inputs()
        #                                 data['outputs'] = tx.serialize_outputs()
        #                  without needing the if statement here.
        if not self.is_block:
            for input_self in self.inputs:
                data_input: Dict[str, Any] = {}
                data_input['tx_id'] = input_self.tx_id.hex()
                data_input['index'] = input_self.index
                data_input['data'] = base64.b64encode(input_self.data).decode('utf-8')
                data['inputs'].append(data_input)

        data['outputs'] = []
        for output in self.outputs:
            data_output: Dict[str, Any] = {}
            data_output['value'] = output.value
            data_output['script'] = base64.b64encode(output.script).decode('utf-8')
            if decode_script:
                data_output['decoded'] = output.to_human_readable()
            data['outputs'].append(data_output)

        data['tokens'] = [uid.hex() for uid in self.tokens]

        return data

    @abstractmethod
    def to_proto(self, include_metadata: bool = True) -> protos.BaseTransaction:
        """ Creates a Protobuf object from self

        :param include_metadata: Whether to include metadata, regardless if there is
        :type include_metadata: bool

        :return: Protobuf object
        :rtype: :py:class:`hathor.protos.BaseTransaction`
        """
        raise NotImplementedError

    def validate_tx_error(self) -> Tuple[bool, str]:
        """ Verify if tx is valid and return success and possible error message

            :return: Success if tx is valid and possible error message, if not
            :rtype: tuple[bool, str]
        """
        success = True
        message = ''
        try:
            self.verify()
        except TxValidationError as e:
            success = False
            message = str(e)
        return success, message

    def clone(self) -> 'BaseTransaction':
        """Return exact copy without sharing memory, including metadata if loaded.

        :return: Transaction or Block copy
        """
        new_tx = self.create_from_struct(self.get_struct())
        if hasattr(self, '_metadata'):
            new_tx._metadata = self._metadata.clone()
        new_tx.storage = self.storage
        return new_tx

    def get_token_uid(self, index: int) -> bytes:
        """Returns the token uid with corresponding index from the tx token uid list.

        Hathor always has index 0, but we don't include it in the token uid list, so other tokens are
        always 1-off. This means that token with index 1 is the first in the list.

        :param index: token index on the token uid list
        :type index: int

        :return: the token uid
        :rtype: bytes
        """
        if index == 0:
            return HATHOR_TOKEN_UID
        return self.tokens[index - 1]


class TxInput:
    _tx: BaseTransaction  # XXX: used for caching on hathor.transaction.Transaction.get_spent_tx

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

    def to_human_readable(self):
        """Returns dict of Input information, ready to be serialized

        :rtype: Dict
        """
        return {
            'tx_id': self.tx_id.hex(),  # string
            'index': self.index,  # int
            'data':
                base64.b64encode(self.data).decode('utf-8')  # string
        }

    @classmethod
    def create_from_proto(cls, input_proto: protos.TxInput) -> 'TxInput':
        """ Creates a TxInput from a protobuf TxInput object

        :param input_proto: Bytes of a serialized output
        :return: An input
        """
        return cls(
            tx_id=input_proto.tx_id,
            index=input_proto.index,
            data=input_proto.data,
        )

    def to_proto(self) -> protos.TxInput:
        """ Creates a Protobuf object from self

        :return: Protobuf object
        :rtype: :py:class:`hathor.protos.TxInput`
        """
        return protos.TxInput(
            tx_id=self.tx_id,
            index=self.index,
            data=self.data,
        )


class TxOutput:

    # first bit in the index byte indicates whether it's an authority output
    TOKEN_INDEX_MASK = 0b01111111
    TOKEN_AUTHORITY_MASK = 0b10000000

    # last bit indicates a token uid creation UTXO
    TOKEN_CREATION_MASK = 0b00000001
    # second to last bit is mint authority
    TOKEN_MINT_MASK = 0b00000010
    # and next one is melt authority
    TOKEN_MELT_MASK = 0b00000100

    def __init__(self, value: int, script: bytes, token_data: int = 0) -> None:
        """
            value: amount spent (4 bytes)
            script: script in bytes
            token_data: index of the token uid in the uid list
        """
        assert isinstance(value, int), 'value is %s, type %s' % (str(value), type(value))
        assert isinstance(script, bytes), 'script is %s, type %s' % (str(script), type(script))
        assert isinstance(token_data, int), 'token_data is %s, type %s' % (str(token_data), type(token_data))
        assert value <= MAX_OUTPUT_VALUE

        self.value = value  # int
        self.script = script  # bytes
        self.token_data = token_data  # int

    def get_token_index(self) -> int:
        """The token uid index in the list"""
        return self.token_data & self.TOKEN_INDEX_MASK

    def is_token_authority(self) -> bool:
        """Whether this is a token authority output"""
        return (self.token_data & self.TOKEN_AUTHORITY_MASK) > 0

    def is_token_creation(self) -> bool:
        """Whether this is a token creation output"""
        return self.is_token_authority() and ((self.value & self.TOKEN_CREATION_MASK) > 0)

    def can_mint_token(self) -> bool:
        """Whether this utxo can mint tokens"""
        return self.is_token_authority() and ((self.value & self.TOKEN_MINT_MASK) > 0)

    def can_melt_token(self) -> bool:
        """Whether this utxo can melt tokens"""
        return self.is_token_authority() and ((self.value & self.TOKEN_MELT_MASK) > 0)

    def to_human_readable(self):
        """Checks what kind of script this is and returns it in human readable form
        """
        from hathor.transaction.scripts import parse_address_script, NanoContractMatchValues

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

    @classmethod
    def create_from_proto(cls, output_proto: protos.TxOutput) -> 'TxOutput':
        """ Creates a TxOutput from a protobuf TxOutput object

        :param output_proto: Bytes of a serialized output
        :type output_proto: :py:class:`hathor.protos.TxOutput`

        :return: An output
        :rtype: TxOutput
        """
        return cls(
            value=output_proto.value,
            script=output_proto.script,
            token_data=output_proto.token_data,
        )

    def to_proto(self) -> protos.TxOutput:
        """ Creates a Protobuf object from self

        :return: Protobuf object
        """
        return protos.TxOutput(
            value=self.value,
            script=self.script,
            token_data=self.token_data,
        )


def bytes_to_output_value(buf: bytes) -> Tuple[int, bytes]:
    (value_high_byte,), _ = unpack('!b', buf)
    if value_high_byte < 0:
        output_struct = '!q'
        value_sign = -1
    else:
        output_struct = '!i'
        value_sign = 1
    (signed_value,), buf = unpack(output_struct, buf)
    value = signed_value * value_sign
    assert value >= 0
    if value < _MAX_OUTPUT_VALUE_32 and value_high_byte < 0:
        raise ValueError('Value fits in 4 bytes but is using 8 bytes')
    return value, buf


def output_value_to_bytes(number: int) -> bytes:
    if number > _MAX_OUTPUT_VALUE_32:
        return (-number).to_bytes(8, byteorder='big', signed=True)
    else:
        return number.to_bytes(4, byteorder='big', signed=True)  # `signed` makes no difference, but oh well


def tx_or_block_from_proto(tx_proto: protos.BaseTransaction,
                           storage: Optional['TransactionStorage'] = None) -> 'BaseTransaction':
    from hathor.transaction.transaction import Transaction
    from hathor.transaction.block import Block
    if tx_proto.HasField('transaction'):
        return Transaction.create_from_proto(tx_proto, storage=storage)
    elif tx_proto.HasField('block'):
        return Block.create_from_proto(tx_proto, storage=storage)
    else:
        raise ValueError('invalid base_transaction_oneof')
