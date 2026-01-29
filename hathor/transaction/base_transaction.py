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

import time
import weakref
from abc import abstractmethod
from enum import IntEnum
from itertools import chain
from math import log
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Iterator, Optional, TypeAlias, TypeVar

from structlog import get_logger
from typing_extensions import Self

from hathor.checkpoint import Checkpoint
from hathor.conf.get_settings import get_global_settings
from hathor.transaction.headers import VertexBaseHeader
from hathor.transaction.static_metadata import VertexStaticMetadata
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.transaction.util import VerboseCallback
from hathor.transaction.validation_state import ValidationState
from hathor.types import VertexId
from hathor.util import classproperty
from hathor.utils.weight import weight_to_work
from hathorlib import GenericVertex as LibGenericVertex, TxInput, TxOutput

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Transaction
    from hathor.transaction.storage import TransactionStorage  # noqa: F401
    from hathor.transaction.vertex_children import VertexChildren

logger = get_logger()

MAX_OUTPUT_VALUE = 2**63  # max value (inclusive) that is possible to encode: 9223372036854775808 ~= 9.22337e+18

TX_HASH_SIZE = 32   # 256 bits, 32 bytes

# H = unsigned short (2 bytes), d = double(8), f = float(4), I = unsigned int (4),
# Q = unsigned long long int (64), B = unsigned char (1 byte)

# Signal bits (B), version (B), inputs len (B), and outputs len (B), token uids len (B).
_SIGHASH_ALL_FORMAT_STRING = '!BBBBB'

# Weight (d), timestamp (I), and parents len (B)
_GRAPH_FORMAT_STRING = '!dIB'

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


class GenericVertex(LibGenericVertex, Generic[StaticMetadataT]):
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

        super().__init__()

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
        d = super()._get_formatted_fields_dict(short)
        if not short:
            d.update(storage=self.storage)
        return d

    # FIXME: VertexParser should work the same on hathorlib and then we can remove this method.
    def get_header_from_bytes(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        """Parse bytes and return the next header in buffer."""
        from hathor.transaction.vertex_parser import VertexParser

        if len(self.headers) >= self.get_maximum_number_of_headers():
            raise ValueError('too many headers')
        header_type = buf[:1]
        header_class = VertexParser.get_header_parser(header_type, self._settings)
        header, buf = header_class.deserialize(self, buf)
        self.headers.append(header)
        return buf

    def set_storage(self, storage: 'TransactionStorage'):
        """ Transaction Storage setter
        """
        self.storage = storage

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
        from hathorlib.scripts import parse_address_script

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

    def update_hash(self) -> None:
        """ Update the hash of the transaction.
        """
        super().update_hash()
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
        data = super().to_json(decode_script)

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
        new_tx = self.create_from_struct(self.get_struct())
        if include_storage and self.storage is not None:
            new_tx.set_storage(self.storage)
        # static_metadata can be safely copied as it is a frozen dataclass
        new_tx.set_static_metadata(self._static_metadata)
        if hasattr(self, '_metadata') and include_metadata:
            assert self._metadata is not None  # FIXME: is this actually true or do we have to check if not None
            new_tx._metadata = self._metadata.clone()
        return new_tx

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
