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

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Optional

from hathor.conf.get_settings import get_global_settings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.types import MetaNCCallRecord
from hathor.transaction.validation_state import ValidationState
from hathor.util import collect_n, json_dumpb, json_loadb, practically_equal
from hathor.utils.weight import work_to_weight

if TYPE_CHECKING:
    from weakref import ReferenceType  # noqa: F401

    from hathor.conf.settings import HathorSettings
    from hathor.transaction import BaseTransaction
    from hathor.transaction.storage import TransactionStorage


_MAX_JSON_CHILDREN = 100


class TransactionMetadata:
    hash: Optional[bytes]
    spent_outputs: dict[int, list[bytes]]
    # XXX: the following Optional[] types use None to replace empty set/list to reduce memory use
    conflict_with: Optional[list[bytes]]
    voided_by: Optional[set[bytes]]
    received_by: list[int]
    twins: list[bytes]
    accumulated_weight: int
    first_block: Optional[bytes]
    validation: ValidationState

    # Used to store the root node id of the contract tree related to this block.
    nc_block_root_id: Optional[bytes]
    nc_execution: Optional[NCExecutionState]
    nc_calls: Optional[list[MetaNCCallRecord]]
    # Stores events emitted during nano contract execution
    nc_events: Optional[list[tuple[bytes, bytes]]]  # [(nc_id, event_data)]

    # A dict of features in the feature activation process and their respective state. Must only be used by Blocks,
    # is None otherwise. This is only used for caching, so it can be safely cleared up, as it would be recalculated
    # when necessary.
    feature_states: Optional[dict[Feature, FeatureState]] = None
    # It must be a weakref.
    _tx_ref: Optional['ReferenceType[BaseTransaction]']

    # Used to detect changes in voided_by.
    _last_voided_by_hash: Optional[int]
    _last_spent_by_hash: Optional[int]

    def __init__(
        self,
        spent_outputs: Optional[dict[int, list[bytes]]] = None,
        hash: Optional[bytes] = None,
        accumulated_weight: int = 0,
        nc_block_root_id: Optional[bytes] = None,
        settings: HathorSettings | None = None,
    ) -> None:
        from hathor.transaction.genesis import is_genesis

        # Hash of the transaction.
        self.hash = hash
        self._tx_ref = None

        # Nano contract metadata
        self.nc_block_root_id = nc_block_root_id
        self.nc_execution = None
        self.nc_calls = None
        self.nc_events = None

        # Tx outputs that have been spent.
        # The key is the output index, while the value is a set of the transactions which spend the output.
        self.spent_outputs = spent_outputs or defaultdict(list)
        self._last_spent_by_hash = None

        # FIXME: conflict_with -> conflicts_with (as in "this transaction conflicts with these ones")
        # Hash of the transactions that conflicts with this transaction.
        self.conflict_with = None

        # - Hashes of the transactions that void this transaction.
        # - When a transaction has a conflict and is voided because of this conflict, its own hash is added to
        # voided_by. The logic is that the transaction is voiding itself.
        # - When a block is voided, its own hash is added to voided_by.
        # - When it is constructed it will be voided by "partially validated" until it is validated
        self.voided_by = None
        self._last_voided_by_hash = None

        # List of peers which have sent this transaction.
        # Store only the peers' id.
        self.received_by = []

        # Hash of the transactions that are twin to this transaction.
        # Twin transactions have the same inputs and outputs
        self.twins = []

        # Accumulated weight
        self.accumulated_weight = accumulated_weight

        # First valid block that verifies this transaction
        # If two blocks verify the same parent block and have the same score, both are valid.
        self.first_block = None

        # Validation
        self.validation = ValidationState.INITIAL

        settings = settings or get_global_settings()

        # Genesis specific:
        if hash is not None and is_genesis(hash, settings=settings):
            self.validation = ValidationState.FULL

    def get_tx(self) -> 'BaseTransaction':
        assert self._tx_ref is not None
        tx = self._tx_ref()
        assert tx is not None
        return tx

    def get_output_spent_by(self, index: int) -> Optional[bytes]:
        tx = self.get_tx()
        assert tx.storage is not None
        spent_set = self.spent_outputs[index]
        spent_by = None
        for h in spent_set:
            tx2 = tx.storage.get_transaction(h)
            tx2_meta = tx2.get_metadata()
            if not bool(tx2_meta.voided_by):
                # There may be only one spent_by.
                assert spent_by is None
                spent_by = tx2.hash
        return spent_by

    def has_spent_by_changed_since_last_call(self) -> bool:
        """Check whether `self.get_output_spent_by(...)` has been changed since the last call to this same method.
        Notice that it will always return True when the transaction is first loaded into memory.

        >>> meta = TransactionMetadata()
        >>> b1 = meta.has_spent_by_changed_since_last_call()
        >>> b2 = meta.has_spent_by_changed_since_last_call()
        >>> assert b1 != b2
        """
        cur_hash = hash(tuple((index, self.get_output_spent_by(index)) for index in self.spent_outputs.keys()))
        if self._last_spent_by_hash != cur_hash:
            self._last_spent_by_hash = cur_hash
            return True
        return False

    def has_voided_by_changed_since_last_call(self) -> bool:
        """Check whether `self.voided_by` has been changed since the last call to this same method.
        Notice that it will always return True when the transaction is first loaded into memory.

        >>> meta = TransactionMetadata()
        >>> meta.voided_by = {b'pretend_this_is_a_tx_hash'}
        >>> b1 = meta.has_voided_by_changed_since_last_call()
        >>> b2 = meta.has_voided_by_changed_since_last_call()
        >>> assert b1 != b2
        """
        cur_hash = hash(frozenset(self.voided_by)) if self.voided_by else None
        if self._last_voided_by_hash != cur_hash:
            self._last_voided_by_hash = cur_hash
            return True
        return False

    def __eq__(self, other: Any) -> bool:
        """Override the default Equals behavior"""
        if not isinstance(other, TransactionMetadata):
            return False
        for field in ['hash', 'conflict_with', 'voided_by', 'received_by',
                      'accumulated_weight', 'twins', 'first_block', 'validation',
                      'feature_states', 'nc_block_root_id', 'nc_calls', 'nc_execution', 'nc_events']:
            if (getattr(self, field) or None) != (getattr(other, field) or None):
                return False

        # Compare self.spent_outputs separately because it is a defaultdict.
        # We need to do this because a simple access to a key may have side effects.
        # For example:
        #     >>> a = defaultdict(list)
        #     >>> b = defaultdict(list)
        #     >>> a == b
        #     True
        #     >>> a[0]
        #     []
        #     >>> a == b
        #     False
        if not practically_equal(self.spent_outputs, other.spent_outputs):
            return False

        return True

    def to_storage_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        data['hash'] = self.hash and self.hash.hex()
        data['spent_outputs'] = []
        for idx, hashes in self.spent_outputs.items():
            data['spent_outputs'].append([idx, [h_bytes.hex() for h_bytes in hashes]])
        data['received_by'] = list(self.received_by)
        data['conflict_with'] = [x.hex() for x in set(self.conflict_with)] if self.conflict_with else []
        data['voided_by'] = [x.hex() for x in self.voided_by] if self.voided_by else []
        data['twins'] = [x.hex() for x in self.twins]
        data['accumulated_weight_raw'] = str(self.accumulated_weight)

        vertex = self.get_tx()
        data['min_height'] = vertex.static_metadata.min_height

        from hathor.transaction import Block
        if isinstance(vertex, Block):
            data['height'] = vertex.static_metadata.height
            data['score'] = vertex.static_metadata.score
            data['min_height'] = vertex.static_metadata.min_height
            data['feature_activation_bit_counts'] = vertex.static_metadata.feature_activation_bit_counts
        else:
            # TODO: This is kept here backwards compatibility with transactions,
            #  but should be removed in the future.
            data['height'] = 0
            data['score'] = 0
            data['min_height'] = 0
            data['feature_activation_bit_counts'] = []

        data['score_raw'] = str(data['score'])

        if self.feature_states is not None:
            data['feature_states'] = {feature.value: state.value for feature, state in self.feature_states.items()}

        if self.first_block is not None:
            data['first_block'] = self.first_block.hex()
        else:
            data['first_block'] = None
        data['validation'] = self.validation.name.lower()
        data['nc_block_root_id'] = self.nc_block_root_id.hex() if self.nc_block_root_id else None
        data['nc_calls'] = [x.to_json() for x in self.nc_calls] if self.nc_calls else None
        data['nc_execution'] = self.nc_execution.value if self.nc_execution else None
        # Serialize nc_events: [(nc_id, event_data)]
        if self.nc_events:
            data['nc_events'] = [(nc_id.hex(), event_data.hex()) for nc_id, event_data in self.nc_events]
        else:
            data['nc_events'] = None
        return data

    def to_json(self) -> dict[str, Any]:
        data = self.to_storage_json()
        data['accumulated_weight'] = work_to_weight(self.accumulated_weight)

        limited_children, has_more_children = collect_n(iter(self.get_tx().get_children()), _MAX_JSON_CHILDREN)
        data['children'] = [child_id.hex() for child_id in limited_children]
        data['has_more_children'] = has_more_children

        return data

    def to_json_extended(self, tx_storage: 'TransactionStorage') -> dict[str, Any]:
        data = self.to_json()
        first_block_height: Optional[int]
        if self.first_block is not None:
            first_block = tx_storage.get_block(self.first_block)
            first_block_height = first_block.static_metadata.height
        else:
            first_block_height = None
        data['first_block_height'] = first_block_height
        return data

    @classmethod
    def create_from_json(cls, data: dict[str, Any]) -> 'TransactionMetadata':
        hash_ = bytes.fromhex(data['hash']) if data['hash'] else None
        meta = cls(hash=hash_)
        for idx, hashes in data['spent_outputs']:
            for h_hex in hashes:
                meta.spent_outputs[idx].append(bytes.fromhex(h_hex))
        meta.received_by = list(data['received_by'])

        if 'conflict_with' in data and data['conflict_with']:
            meta.conflict_with = [bytes.fromhex(h) for h in set(data['conflict_with'])]
        else:
            meta.conflict_with = None

        if 'voided_by' in data:
            meta.voided_by = set(bytes.fromhex(h) for h in data['voided_by']) if data['voided_by'] else None
        else:
            meta.voided_by = None

        if 'twins' in data:
            meta.twins = [bytes.fromhex(h) for h in data['twins']]
        else:
            meta.twins = []

        meta.accumulated_weight = int(data['accumulated_weight_raw'])

        feature_states_raw = data.get('feature_states')
        if feature_states_raw:
            meta.feature_states = {
                Feature(feature): FeatureState(feature_state)
                for feature, feature_state in feature_states_raw.items()
            }

        first_block_raw = data.get('first_block', None)
        if first_block_raw:
            meta.first_block = bytes.fromhex(first_block_raw)

        _val_name = data.get('validation', None)
        meta.validation = ValidationState.from_name(_val_name) if _val_name is not None else ValidationState.INITIAL

        nc_block_root_id_raw = data.get('nc_block_root_id')
        if nc_block_root_id_raw is not None:
            meta.nc_block_root_id = bytes.fromhex(nc_block_root_id_raw)
        else:
            meta.nc_block_root_id = None

        nc_execution_raw = data.get('nc_execution')
        if nc_execution_raw is not None:
            meta.nc_execution = NCExecutionState(nc_execution_raw)
        else:
            meta.nc_execution = None

        nc_calls_raw = data.get('nc_calls')
        if nc_calls_raw is not None:
            meta.nc_calls = [MetaNCCallRecord.from_json(x) for x in nc_calls_raw]
        else:
            meta.nc_calls = None

        nc_events_raw = data.get('nc_events')
        if nc_events_raw is not None:
            meta.nc_events = [(bytes.fromhex(nc_id), bytes.fromhex(event_data))
                              for nc_id, event_data in nc_events_raw]
        else:
            meta.nc_events = None

        return meta

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TransactionMetadata':
        """Deserialize a TransactionMetadata instance from bytes."""
        return cls.create_from_json(json_loadb(data))

    def to_bytes(self) -> bytes:
        """Serialize a TransactionMetadata instance to bytes. This should be used for storage."""
        json_dict = self.to_storage_json()

        # The `to_json()` method includes these fields for backwards compatibility with APIs, but since they're not
        # part of metadata, they should not be serialized.
        if 'height' in json_dict:
            del json_dict['height']
        if 'score' in json_dict:
            del json_dict['score']
        if 'score_raw' in json_dict:
            del json_dict['score_raw']
        if 'min_height' in json_dict:
            del json_dict['min_height']
        if 'feature_activation_bit_counts' in json_dict:
            del json_dict['feature_activation_bit_counts']
        # TODO: This one has not been migrated yet, but will be in a future PR
        # if 'feature_states' in json_dict:
        #     del json_dict['feature_states']

        return json_dumpb(json_dict)

    def clone(self) -> 'TransactionMetadata':
        """Return exact copy without sharing memory.

        :return: TransactionMetadata
        :rtype: :py:class:`hathor.transaction.TransactionMetadata`
        """
        # XXX: using json serialization for simplicity, should it use pickle? manual fields? other alternative?
        return self.create_from_json(self.to_storage_json())

    def add_voided_by(self, item: bytes) -> None:
        """Add `item` to `self.voided_by`. Note that this method does not save the change."""
        if not self.voided_by:
            self.voided_by = {item}
        else:
            self.voided_by.add(item)

    def del_voided_by(self, item: bytes) -> None:
        """Deletes `item` from `self.voided_by`. Note that this method does not save the change."""
        if self.voided_by is not None:
            self.voided_by.discard(item)
            if not self.voided_by:
                self.voided_by = None

    def get_frozen_voided_by(self) -> frozenset[bytes]:
        """Return a frozen set copy of voided_by."""
        if self.voided_by is None:
            return frozenset()
        return frozenset(self.voided_by)

    def is_in_voided_by(self, item: bytes) -> bool:
        """Return True if item exists in voided_by."""
        if self.voided_by is None:
            return False
        return item in self.voided_by
