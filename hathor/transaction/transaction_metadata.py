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

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Optional

from hathor.conf.get_settings import get_global_settings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction.validation_state import ValidationState
from hathor.util import practically_equal

if TYPE_CHECKING:
    from weakref import ReferenceType  # noqa: F401

    from hathor.transaction import BaseTransaction
    from hathor.transaction.storage import TransactionStorage


class TransactionMetadata:
    hash: Optional[bytes]
    spent_outputs: dict[int, list[bytes]]
    # XXX: the following Optional[] types use None to replace empty set/list to reduce memory use
    conflict_with: Optional[list[bytes]]
    voided_by: Optional[set[bytes]]
    received_by: list[int]
    children: list[bytes]
    twins: list[bytes]
    accumulated_weight: float
    score: float
    first_block: Optional[bytes]
    height: Optional[int]
    _validation: ValidationState
    # XXX: this is only used to defer the reward-lock verification from the transaction spending a reward to the first
    # block that confirming this transaction, it is important to always have this set to be able to distinguish an old
    # metadata (that does not have this calculated, from a tx with a new format that does have this calculated)
    min_height: Optional[int]

    # A list of feature activation bit counts. Must only be used by Blocks, is None otherwise.
    # Each list index corresponds to a bit position, and its respective value is the rolling count of active bits from
    # the previous boundary block up to this block, including it. LSB is on the left.
    feature_activation_bit_counts: Optional[list[int]]

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
        accumulated_weight: float = 0,
        score: float = 0,
        height: Optional[int] = None,
        min_height: Optional[int] = None,
        feature_activation_bit_counts: Optional[list[int]] = None
    ) -> None:
        from hathor.transaction.genesis import is_genesis
        self._settings = get_global_settings()

        # Hash of the transaction.
        self.hash = hash
        self._tx_ref = None

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
        self.voided_by = {self._settings.PARTIALLY_VALIDATED_ID}
        self._last_voided_by_hash = None

        # List of peers which have sent this transaction.
        # Store only the peers' id.
        self.received_by = []

        # List of transactions which have this transaction as parent.
        # Store only the transactions' hash.
        self.children = []

        # Hash of the transactions that are twin to this transaction.
        # Twin transactions have the same inputs and outputs
        self.twins = []

        # Accumulated weight
        self.accumulated_weight = accumulated_weight

        # Score
        self.score = score

        # First valid block that verifies this transaction
        # If two blocks verify the same parent block and have the same score, both are valid.
        self.first_block = None

        # Height
        self.height = height

        # Min height
        self.min_height = min_height

        # Validation
        self._validation = ValidationState.INITIAL

        self.feature_activation_bit_counts = feature_activation_bit_counts

        # Genesis specific:
        if hash is not None and is_genesis(hash, settings=self._settings):
            self._validation = ValidationState.FULL
            self.voided_by = None

    @property
    def validation(self) -> ValidationState:
        return self._validation

    @validation.setter
    def validation(self, validation: ValidationState) -> None:
        self._validation = validation
        if validation.is_fully_connected():
            self.del_voided_by(self._settings.PARTIALLY_VALIDATED_ID)
        else:
            self.add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)

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
        for field in ['hash', 'conflict_with', 'voided_by', 'received_by', 'children',
                      'accumulated_weight', 'twins', 'score', 'first_block', 'validation',
                      'min_height', 'feature_activation_bit_counts', 'feature_states']:
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

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        data['hash'] = self.hash and self.hash.hex()
        data['spent_outputs'] = []
        for idx, hashes in self.spent_outputs.items():
            data['spent_outputs'].append([idx, [h_bytes.hex() for h_bytes in hashes]])
        data['received_by'] = list(self.received_by)
        data['children'] = [x.hex() for x in self.children]
        data['conflict_with'] = [x.hex() for x in set(self.conflict_with)] if self.conflict_with else []
        data['voided_by'] = [x.hex() for x in self.voided_by] if self.voided_by else []
        data['twins'] = [x.hex() for x in self.twins]
        data['accumulated_weight'] = self.accumulated_weight
        data['score'] = self.score
        data['height'] = self.height
        data['min_height'] = self.min_height
        data['feature_activation_bit_counts'] = self.feature_activation_bit_counts

        if self.feature_states is not None:
            data['feature_states'] = {feature.value: state.value for feature, state in self.feature_states.items()}

        if self.first_block is not None:
            data['first_block'] = self.first_block.hex()
        else:
            data['first_block'] = None
        data['validation'] = self.validation.name.lower()
        return data

    def to_json_extended(self, tx_storage: 'TransactionStorage') -> dict[str, Any]:
        data = self.to_json()
        first_block_height: Optional[int]
        if self.first_block is not None:
            first_block = tx_storage.get_transaction(self.first_block)
            first_block_height = first_block.get_metadata().height
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
        meta.children = [bytes.fromhex(h) for h in data['children']]

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

        meta.accumulated_weight = data['accumulated_weight']
        meta.score = data.get('score', 0)
        meta.height = data.get('height', 0)  # XXX: should we calculate the height if it's not defined?
        meta.min_height = data.get('min_height')
        meta.feature_activation_bit_counts = data.get('feature_activation_bit_counts', [])

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

        return meta

    def clone(self) -> 'TransactionMetadata':
        """Return exact copy without sharing memory.

        :return: TransactionMetadata
        :rtype: :py:class:`hathor.transaction.TransactionMetadata`
        """
        # XXX: using json serialization for simplicity, should it use pickle? manual fields? other alternative?
        return self.create_from_json(self.to_json())

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
