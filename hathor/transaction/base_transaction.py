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

from __future__ import annotations

import base64
import datetime
import hashlib
import time
import weakref
from abc import ABC, abstractmethod
from enum import IntEnum
from itertools import chain
from math import isfinite, log
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Iterator, Optional, TypeAlias, TypeVar

from structlog import get_logger
from typing_extensions import Self

from hathor.checkpoint import Checkpoint
from hathor.conf.get_settings import get_global_settings
from hathor.transaction.exceptions import InvalidOutputValue, WeightError
from hathor.transaction.headers import VertexBaseHeader
from hathor.transaction.static_metadata import VertexStaticMetadata
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.transaction.util import VerboseCallback
from hathor.transaction.validation_state import ValidationState
from hathor.types import TokenUid, TxOutputScript, VertexId
from hathor.util import classproperty
from hathor.utils.weight import weight_to_work

if TYPE_CHECKING:
    from _hashlib import HASH

    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Transaction
    from hathor.transaction.storage import TransactionStorage  # noqa: F401
    from hathor.transaction.vertex_children import VertexChildren

logger = get_logger()

MAX_OUTPUT_VALUE = 2**63  # max value (inclusive) that is possible to encode: 9223372036854775808 ~= 9.22337e+18

TX_HASH_SIZE = 32   # 256 bits, 32 bytes

# The int value of one byte
_ONE_BYTE = 0xFF


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


# Versions are sequential for blocks and transactions
class TxVersion(IntEnum):
    REGULAR_BLOCK = 0
    REGULAR_TRANSACTION = 1
    TOKEN_CREATION_TRANSACTION = 2
    MERGE_MINED_BLOCK = 3
    # DEPRECATED_NANO_CONTRACT = 4  # XXX: Temporary to keep compatibility
    POA_BLOCK = 5
    ON_CHAIN_BLUEPRINT = 6

    @classmethod
    def _missing_(cls, value: Any) -> None:
        assert isinstance(value, int), f"Value '{value}' must be an integer"
        assert value <= _ONE_BYTE, f'Value {hex(value)} must not be larger than one byte'

        raise ValueError(f'Invalid version: {value}')

    def get_cls(self) -> type['BaseTransaction']:
        from hathor.transaction.block import Block
        from hathor.transaction.merge_mined_block import MergeMinedBlock
        from hathor.transaction.poa import PoaBlock
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        from hathor.transaction.transaction import Transaction

        cls_map: dict[TxVersion, type[BaseTransaction]] = {
            TxVersion.REGULAR_BLOCK: Block,
            TxVersion.REGULAR_TRANSACTION: Transaction,
            TxVersion.TOKEN_CREATION_TRANSACTION: TokenCreationTransaction,
            TxVersion.MERGE_MINED_BLOCK: MergeMinedBlock,
            TxVersion.POA_BLOCK: PoaBlock
        }

        settings = get_global_settings()
        if settings.ENABLE_NANO_CONTRACTS:
            from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint
            cls_map[TxVersion.ON_CHAIN_BLUEPRINT] = OnChainBlueprint

        cls = cls_map.get(self)

        if cls is None:
            raise ValueError('Invalid version.')
        else:
            return cls


_base_transaction_log = logger.new()

StaticMetadataT = TypeVar('StaticMetadataT', bound=VertexStaticMetadata, covariant=True)


class GenericVertex(ABC, Generic[StaticMetadataT]):
    """Hathor generic vertex"""

    __slots__ = ['version', 'signal_bits', 'weight', 'timestamp', 'nonce', 'inputs', 'outputs', 'parents', '_hash',
                 'storage', '_settings', '_metadata', '_static_metadata', 'headers', 'name', 'MAX_NUM_INPUTS',
                 'MAX_NUM_OUTPUTS', '__weakref__']

    # Even though nonce is serialized with different sizes for tx and blocks
    # the same size is used for hashes to enable mining algorithm compatibility
    SERIALIZATION_NONCE_SIZE: ClassVar[int]
    HASH_NONCE_SIZE = 16
    HEX_BASE = 16

    _metadata: Optional[TransactionMetadata]
    _static_metadata: StaticMetadataT | None

    # Bits extracted from the first byte of the version field. They carry extra information that may be interpreted
    # differently by each subclass of BaseTransaction.
    # Currently only the Block subclass uses it, carrying information about Feature Activation bits and also extra
    # bits reserved for future use, depending on the configuration.
    signal_bits: int

    def __init__(
        self,
        nonce: int = 0,
        timestamp: Optional[int] = None,
        signal_bits: int = 0,
        version: TxVersion = TxVersion.REGULAR_BLOCK,
        weight: float = 0,
        inputs: Optional[list['TxInput']] = None,
        outputs: Optional[list['TxOutput']] = None,
        parents: Optional[list[VertexId]] = None,
        hash: Optional[VertexId] = None,
        storage: Optional['TransactionStorage'] = None,
        settings: HathorSettings | None = None,
    ) -> None:
        """
            Nonce: nonce used for the proof-of-work
            Timestamp: moment of creation
            Signal bits: bits used to carry extra information that may be interpreted differently by each subclass
            Version: version when it was created
            Weight: different for transactions and blocks
            Outputs: all outputs that are being created
            Parents: transactions you are confirming (2 transactions and 1 block - in case of a block only)
        """
        assert signal_bits <= _ONE_BYTE, f'signal_bits {hex(signal_bits)} must not be larger than one byte'
        assert version <= _ONE_BYTE, f'version {hex(version)} must not be larger than one byte'

        self._settings = settings or get_global_settings()
        self.nonce = nonce
        self.timestamp = timestamp or int(time.time())
        self.signal_bits = signal_bits
        self.version = version
        self.weight = weight
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.parents = parents or []
        self.storage = storage
        self._hash: VertexId | None = hash  # Stored as bytes.
        self._static_metadata = None

        self.headers: list[VertexBaseHeader] = []

        # A name solely for debugging purposes.
        self.name: str | None = None

        self.MAX_NUM_INPUTS = self._settings.MAX_NUM_INPUTS
        self.MAX_NUM_OUTPUTS = self._settings.MAX_NUM_OUTPUTS

    @classproperty
    def log(cls):
        """ This is a workaround because of a bug on structlog (or abc).

        See: https://github.com/hynek/structlog/issues/229
        """
        return _base_transaction_log

    def _get_formatted_fields_dict(self, short: bool = True) -> dict[str, str]:
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
                storage=repr(self.storage),
            )
        return d

    def __repr__(self) -> str:
        class_name = type(self).__name__
        return '%s(%s)' % (class_name, ', '.join('%s=%s' % i for i in self._get_formatted_fields_dict(False).items()))

    def __str__(self) -> str:
        class_name = type(self).__name__
        return '%s(%s)' % (class_name, ', '.join('%s=%s' % i for i in self._get_formatted_fields_dict().items()))

    @property
    @abstractmethod
    def is_block(self) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def is_transaction(self) -> bool:
        raise NotImplementedError

    def is_nano_contract(self) -> bool:
        """Return whether this transaction is a nano contract."""
        return False

    def has_fees(self) -> bool:
        """Return whether this transaction has a fee header."""
        return False

    def get_maximum_number_of_headers(self) -> int:
        """Return the maximum number of headers for this vertex."""
        return 2

    @classmethod
    @abstractmethod
    def create_from_struct(cls, struct_bytes: bytes, storage: Optional['TransactionStorage'] = None,
                           *, verbose: VerboseCallback = None) -> Self:
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

    def get_parents(self, *, existing_only: bool = False) -> Iterator['BaseTransaction']:
        """Return an iterator of the parents

        :return: An iterator of the parents
        :rtype: Iter[BaseTransaction]
        """
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        for parent_hash in self.parents:
            assert self.storage is not None
            try:
                yield self.storage.get_transaction(parent_hash)
            except TransactionDoesNotExist:
                if not existing_only:
                    raise

    @property
    def is_genesis(self) -> bool:
        """ Check whether this transaction is a genesis transaction

        :rtype: bool
        """
        if self._hash is None:
            return False
        from hathor.transaction.genesis import is_genesis
        return is_genesis(self.hash, settings=self._settings)

    @abstractmethod
    def get_funds_struct(self) -> bytes:
        """Return the funds data serialization of the vertex.

        :return: funds data serialization of the vertex
        :rtype: bytes
        """
        raise NotImplementedError

    @abstractmethod
    def get_graph_struct(self) -> bytes:
        """Return the graph data serialization of the transaction, without including the nonce field

        :return: graph data serialization of the transaction
        :rtype: bytes
        """
        raise NotImplementedError

    def get_headers_struct(self) -> bytes:
        """Return the serialization of the headers only."""
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser.vertex_serializer import serialize_headers
        serializer = Serializer.build_bytes_serializer()
        serialize_headers(serializer, self)
        return bytes(serializer.finalize())

    def get_struct_without_nonce(self) -> bytes:
        """Return a partial serialization of the transaction, without including the nonce field

        :return: Partial serialization of the transaction
        :rtype: bytes
        """
        return self.get_funds_struct() + self.get_graph_struct()

    def get_struct_nonce(self) -> bytes:
        """Return a partial serialization of the transaction's proof-of-work, which is usually the nonce field

        :return: Partial serialization of the transaction's proof-of-work
        :rtype: bytes
        """
        from hathor.transaction.util import int_to_bytes
        assert self.SERIALIZATION_NONCE_SIZE is not None
        return int_to_bytes(self.nonce, self.SERIALIZATION_NONCE_SIZE)

    def get_struct(self) -> bytes:
        """Return the complete serialization of the transaction

        :rtype: bytes
        """
        return self.get_struct_without_nonce() + self.get_struct_nonce() + self.get_headers_struct()

    def get_all_dependencies(self) -> set[bytes]:
        """Set of all tx-hashes needed to fully validate this tx, including parent blocks/txs and inputs."""
        return set(chain(self.parents, (i.tx_id for i in self.inputs)))

    def get_tx_parents_ids(self) -> set[VertexId]:
        """Set of parent tx hashes, typically used for syncing transactions."""
        return set(self.parents[1:] if self.is_block else self.parents)

    def get_tx_parents(self) -> set[Transaction]:
        """Set of parent txs."""
        assert self.storage is not None
        return set(self.storage.get_tx(parent_id) for parent_id in self.get_tx_parents_ids())

    def get_related_addresses(self) -> set[str]:
        """ Return a set of addresses collected from tx's inputs and outputs.
        """
        from hathor.transaction.scripts import parse_address_script

        assert self.storage is not None
        addresses: set[str] = set()

        def add_address_from_output(output: 'TxOutput') -> None:
            script_type_out = parse_address_script(output.script)
            if script_type_out:
                address = script_type_out.address
                addresses.add(address)

        for txin in self.inputs:
            tx2 = self.storage.get_transaction(txin.tx_id)
            txout = tx2.outputs[txin.index]
            add_address_from_output(txout)

        for txout in self.outputs:
            add_address_from_output(txout)

        return addresses

    def set_validation(self, validation: ValidationState) -> None:
        """ This method will set the internal validation state AND the appropriate voided_by marker.

        NOTE: THIS METHOD WILL NOT SAVE THE TRANSACTION
        """
        meta = self.get_metadata()
        meta.validation = validation
        if validation.is_fully_connected():
            self._unmark_partially_validated()
        else:
            self._mark_partially_validated()

    def validate_checkpoint(self, checkpoints: list[Checkpoint]) -> bool:
        """ Run checkpoint validations  and update the validation state.

        If no exception is raised, the ValidationState will end up as `CHECKPOINT` and return `True`.
        """
        self.verify_checkpoint(checkpoints)
        self.set_validation(ValidationState.CHECKPOINT)
        return True

    def _mark_partially_validated(self) -> None:
        """ This function is used to add the partially-validated mark from the voided-by metadata.

        It is idempotent: calling it multiple time has the same effect as calling it once. But it must only be called
        when the validation state is *NOT* "fully connected", otherwise it'll raise an assertion error.
        """
        tx_meta = self.get_metadata()
        assert not tx_meta.validation.is_fully_connected()
        tx_meta.add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)

    def _unmark_partially_validated(self) -> None:
        """ This function is used to remove the partially-validated mark from the voided-by metadata.

        It is idempotent: calling it multiple time has the same effect as calling it once. But it must only be called
        when the validation state is "fully connected", otherwise it'll raise an assertion error.
        """
        tx_meta = self.get_metadata()
        assert tx_meta.validation.is_fully_connected()
        tx_meta.del_voided_by(self._settings.PARTIALLY_VALIDATED_ID)

    @abstractmethod
    def verify_checkpoint(self, checkpoints: list[Checkpoint]) -> None:
        """Check that this tx is a known checkpoint or is parent of another checkpoint-valid tx/block.

        To be implemented by tx/block, used by `self.validate_checkpoint`. Should not modify the validation state."""
        raise NotImplementedError

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

    def calculate_hash1(self) -> 'HASH':
        """Return the sha256 of the transaction without including the `nonce`

        :return: A partial hash of the transaction
        :rtype: :py:class:`_hashlib.HASH`
        """
        calculate_hash1 = hashlib.sha256()
        calculate_hash1.update(self.get_mining_header_without_nonce())
        return calculate_hash1

    def calculate_hash2(self, part1: 'HASH') -> bytes:
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

    def update_hash(self) -> None:
        """ Update the hash of the transaction.
        """
        self.hash = self.calculate_hash()
        if metadata := getattr(self, '_metadata', None):
            metadata.hash = self.hash

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
            score = weight_to_work(self.weight) if self.is_genesis else 0
            accumulated_weight = weight_to_work(self.weight)
            metadata = TransactionMetadata(
                settings=self._settings,
                hash=self._hash,
                accumulated_weight=accumulated_weight,
                score=score,
            )
            self._metadata = metadata
        if not metadata.hash:
            metadata.hash = self._hash
        metadata._tx_ref = weakref.ref(self)
        return metadata

    def reset_metadata(self) -> None:
        """ Reset transaction's metadata. It is used when a node is initializing and
        recalculating all metadata.
        """
        from hathor.transaction.transaction_metadata import ValidationState
        assert self.storage is not None
        score = weight_to_work(self.weight) if self.is_genesis else 0
        accumulated_weight = weight_to_work(self.weight)
        self._metadata = TransactionMetadata(hash=self._hash,
                                             score=score,
                                             accumulated_weight=accumulated_weight)
        if self.is_genesis:
            self._metadata.validation = ValidationState.CHECKPOINT_FULL
            self._metadata.voided_by = set()
        else:
            self._metadata.validation = ValidationState.INITIAL
            self._metadata.voided_by = {self._settings.PARTIALLY_VALIDATED_ID}
        self._metadata._tx_ref = weakref.ref(self)

        self.storage.save_transaction(self, only_metadata=True)

    def update_accumulated_weight(
        self,
        *,
        stop_value: int | None = None,
        save_file: bool = True,
    ) -> TransactionMetadata:
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
        if stop_value is not None and metadata.accumulated_weight > stop_value:
            return metadata

        work = weight_to_work(self.weight)

        # TODO Another optimization is that, when we calculate the acc weight of a transaction, we
        # also partially calculate the acc weight of its descendants. If it were a DFS, when returning
        # to a vertex, the acc weight calculated would be <= the real acc weight. So, we might store it
        # as a pre-calculated value. Then, during the next DFS, if `cur + tx.acc_weight > stop_value`,
        # we might stop and avoid some visits. Question: how would we do it in the BFS?

        # TODO We can walk by the blocks first, because they have higher weight and this may
        # reduce the number of visits in the BFS. We need to specially handle when a transaction is not
        # directly verified by a block.

        from hathor.transaction.storage.traversal import BFSTimestampWalk
        bfs_walk = BFSTimestampWalk(self.storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        for tx in bfs_walk.run(self, skip_root=True):
            work += weight_to_work(tx.weight)
            if stop_value is not None and work > stop_value:
                break
            bfs_walk.add_neighbors()

        metadata.accumulated_weight = work
        if save_file:
            self.storage.save_transaction(self, only_metadata=True)

        return metadata

    def update_initial_metadata(self, *, save: bool = True) -> None:
        """Update the tx's initial metadata. It does not update the whole metadata.

        It is called when a new transaction/block is received by HathorManager.
        """
        self._update_parents_children_metadata()
        self._update_initial_accumulated_weight()
        if save:
            assert self.storage is not None
            self.storage.save_transaction(self, only_metadata=True)

    def _update_parents_children_metadata(self) -> None:
        """Update the txs/block parent's children metadata."""
        assert self._hash is not None
        assert self.storage is not None

        for parent in self.get_parents(existing_only=True):
            self.storage.vertex_children.add_child(parent, self.hash)

    def _update_initial_accumulated_weight(self) -> None:
        """Update the vertex initial accumulated_weight."""
        metadata = self.get_metadata()
        metadata.accumulated_weight = weight_to_work(self.weight)

    def update_timestamp(self, now: int) -> None:
        """Update this tx's timestamp

        :param now: the current timestamp, in seconds
        :type now: int

        :rtype: None
        """
        assert self.storage is not None
        max_ts_spent_tx = max(self.get_spent_tx(txin).timestamp for txin in self.inputs)
        max_ts_parent = max(parent.timestamp for parent in self.get_parents())
        self.timestamp = max(max_ts_spent_tx + 1, max_ts_parent + 1, now)

    def get_spent_tx(self, input_tx: 'TxInput') -> 'BaseTransaction':
        assert self.storage is not None
        return self.storage.get_transaction(input_tx.tx_id)

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
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

        if include_metadata:
            data['metadata'] = self.get_metadata().to_json()

        return data

    def to_json_extended(self) -> dict[str, Any]:
        assert self.storage is not None

        def serialize_output(tx: BaseTransaction, tx_out: TxOutput) -> dict[str, Any]:
            data = tx_out.to_json(decode_script=True)
            data['token'] = tx.get_token_uid(tx_out.get_token_index()).hex()
            data['decoded'].pop('token_data', None)
            data['decoded'].pop('value', None)
            return data

        meta = self.get_metadata()
        ret: dict[str, Any] = {
            'tx_id': self.hash_hex,
            'version': int(self.version),
            'weight': self.weight,
            'timestamp': self.timestamp,
            'is_voided': bool(meta.voided_by),
            'inputs': [],
            'outputs': [],
            'parents': [],
        }

        # A nano contract tx must be confirmed by one block at least
        # to be considered "executed"
        if meta.first_block is not None:
            ret['first_block'] = meta.first_block.hex()
        else:
            ret['first_block'] = None

        for parent in self.parents:
            ret['parents'].append(parent.hex())

        assert isinstance(ret['inputs'], list)
        assert isinstance(ret['outputs'], list)

        for index, tx_in in enumerate(self.inputs):
            tx2 = self.storage.get_transaction(tx_in.tx_id)
            tx2_out = tx2.outputs[tx_in.index]
            output = serialize_output(tx2, tx2_out)
            output['tx_id'] = tx2.hash_hex
            output['index'] = tx_in.index
            ret['inputs'].append(output)

        for index, tx_out in enumerate(self.outputs):
            spent_by = meta.get_output_spent_by(index)
            output = serialize_output(self, tx_out)
            output['spent_by'] = spent_by.hex() if spent_by else None
            ret['outputs'].append(output)

        return ret

    def clone(self, *, include_metadata: bool = True, include_storage: bool = True) -> Self:
        """Return exact copy without sharing memory, including metadata if loaded.

        :return: Transaction or Block copy
        """
        new_tx = self.create_from_struct(
            self.get_struct(),
            storage=self.storage if include_storage else None,
        )
        # static_metadata can be safely copied as it is a frozen dataclass
        new_tx.set_static_metadata(self._static_metadata)
        if hasattr(self, '_metadata') and include_metadata:
            assert self._metadata is not None  # FIXME: is this actually true or do we have to check if not None
            new_tx._metadata = self._metadata.clone()
        return new_tx

    @abstractmethod
    def get_token_uid(self, index: int) -> TokenUid:
        raise NotImplementedError

    @property
    def static_metadata(self) -> StaticMetadataT:
        """Get this vertex's static metadata. Assumes it has been initialized."""
        assert self._static_metadata is not None
        return self._static_metadata

    @abstractmethod
    def init_static_metadata_from_storage(self, settings: HathorSettings, storage: 'TransactionStorage') -> None:
        """Initialize this vertex's static metadata using dependencies from a storage. This can be called multiple
        times, provided the dependencies don't change. Also, this must be fast, ideally O(1)."""
        raise NotImplementedError

    def set_static_metadata(self, static_metadata: StaticMetadataT | None) -> None:
        """Set this vertex's static metadata. After it's set, it can only be set again to the same value."""
        if self._static_metadata is not None:
            assert self._static_metadata == static_metadata, 'trying to set static metadata with different values'
            self.log.warn(
                'redundant call on set_static_metadata', vertex_id=self.hash_hex, static_metadata=static_metadata
            )

        self._static_metadata = static_metadata

    def get_children(self) -> VertexChildren:
        """Return an iterator of this vertex's children."""
        assert self.storage is not None
        return self.storage.vertex_children.get_children(self)


"""
Type aliases for easily working with `GenericVertex`. A `Vertex` is a superclass that includes all specific
vertex subclasses, and a `BaseTransaction` is simply an alias to `Vertex` for backwards compatibility (it can be
removed in the future).
"""
Vertex: TypeAlias = GenericVertex[VertexStaticMetadata]
BaseTransaction: TypeAlias = Vertex


class TxInput:
    _tx: BaseTransaction  # XXX: used for caching on hathor.transaction.Transaction.get_spent_tx

    def __init__(self, tx_id: VertexId, index: int, data: bytes) -> None:
        """
            tx_id: hash of the transaction that contains the output of this input
            index: index of the output you are spending from transaction tx_id (1 byte)
            data: data to solve output script
        """
        assert isinstance(tx_id, VertexId), 'Value is %s, type %s' % (str(tx_id), type(tx_id))
        assert isinstance(index, int), 'Value is %s, type %s' % (str(index), type(index))
        assert isinstance(data, bytes), 'Value is %s, type %s' % (str(data), type(data))

        self.tx_id = tx_id
        self.index = index
        self.data = data

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return 'TxInput(tx_id=%s, index=%s)' % (self.tx_id.hex(), self.index)

    def __bytes__(self) -> bytes:
        """Returns a byte representation of the input

        :rtype: bytes
        """
        from hathor.transaction.vertex_parser import vertex_serializer
        return vertex_serializer.serialize_tx_input_bytes(self)

    def get_sighash_bytes(self) -> bytes:
        """Return a serialization of the input for the sighash. It always clears the input data.

        :return: Serialization of the input
        :rtype: bytes
        """
        from hathor.transaction.vertex_parser import vertex_serializer
        return vertex_serializer.serialize_tx_input_sighash(self)

    @classmethod
    def create_from_bytes(cls, buf: bytes, *, verbose: VerboseCallback = None) -> tuple['TxInput', bytes]:
        """ Creates a TxInput from a serialized input. Returns the input
        and remaining bytes
        """
        from hathor.transaction.vertex_parser import vertex_serializer
        return vertex_serializer.deserialize_tx_input(buf, verbose=verbose)

    @classmethod
    def create_from_dict(cls, data: dict) -> 'TxInput':
        """ Creates a TxInput from a human readable dict."""
        return cls(
            bytes.fromhex(data['tx_id']),
            int(data['index']),
            base64.b64decode(data['data']) if data.get('data') else b'',
        )

    def to_human_readable(self) -> dict[str, Any]:
        """Returns dict of Input information, ready to be serialized

        :rtype: dict
        """
        return {
            'tx_id': self.tx_id.hex(),  # string
            'index': self.index,  # int
            'data': base64.b64encode(self.data).decode('utf-8')  # string
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

    def __init__(self, value: int, script: TxOutputScript, token_data: int = 0) -> None:
        """
            value: amount spent (4 bytes)
            script: script in bytes
            token_data: index of the token uid in the uid list
        """
        assert isinstance(value, int), 'value is %s, type %s' % (str(value), type(value))
        assert isinstance(script, TxOutputScript), 'script is %s, type %s' % (str(script), type(script))
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
        from hathor.transaction.vertex_parser import vertex_serializer
        return vertex_serializer.serialize_tx_output_bytes(self)

    @classmethod
    def create_from_bytes(cls, buf: bytes, *, verbose: VerboseCallback = None) -> tuple['TxOutput', bytes]:
        """ Creates a TxOutput from a serialized output. Returns the output
        and remaining bytes
        """
        from hathor.transaction.vertex_parser import vertex_serializer
        return vertex_serializer.deserialize_tx_output(buf, verbose=verbose)

    def get_token_index(self) -> int:
        """The token uid index in the list"""
        return self.token_data & self.TOKEN_INDEX_MASK

    def is_token_authority(self) -> bool:
        """Whether this is a token authority output"""
        return (self.token_data & self.TOKEN_AUTHORITY_MASK) > 0

    def is_standard_script(self) -> bool:
        """Return True if this output has a standard script."""
        from hathor.transaction.scripts import P2PKH
        p2pkh = P2PKH.parse_script(self.script)
        if p2pkh is not None:
            return True
        return False

    def can_mint_token(self) -> bool:
        """Whether this utxo can mint tokens"""
        return self.is_token_authority() and ((self.value & self.TOKEN_MINT_MASK) > 0)

    def can_melt_token(self) -> bool:
        """Whether this utxo can melt tokens"""
        return self.is_token_authority() and ((self.value & self.TOKEN_MELT_MASK) > 0)

    def to_human_readable(self) -> dict[str, Any]:
        """Checks what kind of script this is and returns it in human readable form
        """
        from hathor.transaction.scripts import NanoContractMatchValues, parse_address_script

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

    def to_json(self, *, decode_script: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {}
        data['value'] = self.value
        data['token_data'] = self.token_data
        data['script'] = base64.b64encode(self.script).decode('utf-8')
        if decode_script:
            data['decoded'] = self.to_human_readable()
        return data
