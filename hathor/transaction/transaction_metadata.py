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
from enum import IntEnum, unique
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from hathor.util import practically_equal

if TYPE_CHECKING:
    from weakref import ReferenceType  # noqa: F401

    from hathor.transaction import BaseTransaction


@unique
class ValidationState(IntEnum):
    """

    Possible transitions:

    - Initial
        -> Basic: parents exist, graph information checks-out
        -> Invalid: all information to reach `Basic` was available, but something doesn't check out
        -> Checkpoint: is a block which hash matches a known checkpoint is a parent of a Checkpoint-valid tx
    - Basic
        -> Full: all parents reached `Full`, and validation+consensus ran successfully
        -> Invalid: all information to reach `Full` was available, but something doesn't check out
    - Checkpoint
        -> Checkpoint-Full: when all the chain of parents and inputs up to the genesis exist in the database
    - Full: final
    - Checkpoint-Full: final
    - Invalid: final

    `BASIC` means only the validations that can run without access to the dependencies (parents+inputs, except for
    blocks the block parent has to exist and be at least BASIC) have been run. For example, if it's `BASIC` the weight
    of a tx has been validated and is correct, but it may be spending a tx that has already been spent, we will not run
    this validation until _all_ the dependencies have reached `FULL` or any of them `INVALID` (which should
    automatically invalidate this tx). In theory it should be possible to have even more granular validation (if one of
    the inputs exists, validate that we can spend it), but the complexity for that is too high.

    """
    INITIAL = 0  # aka, not validated
    BASIC = 1  # only graph info has been validated
    CHECKPOINT = 2  # validation can be safely assumed because it traces up to a known checkpoint
    FULL = 3  # fully validated
    CHECKPOINT_FULL = 4  # besides being checkpoint valid, it is fully connected
    INVALID = -1  # not valid, this does not mean not best chain, orphan chains can be valid

    def is_initial(self) -> bool:
        """Short-hand property"""
        return self is ValidationState.INITIAL

    def is_at_least_basic(self) -> bool:
        """Until a validation is final, it is possible to change its state when more information is available."""
        return self >= ValidationState.BASIC

    def is_valid(self) -> bool:
        """Short-hand property."""
        return self in {ValidationState.FULL, ValidationState.CHECKPOINT}

    def is_checkpoint(self) -> bool:
        """Short-hand property."""
        return self in {ValidationState.CHECKPOINT, ValidationState.CHECKPOINT_FULL}

    def is_fully_connected(self) -> bool:
        """Short-hand property."""
        return self in {ValidationState.FULL, ValidationState.CHECKPOINT_FULL}

    def is_invalid(self) -> bool:
        """Short-hand property."""
        return self is ValidationState.INVALID

    def is_final(self) -> bool:
        """Until a validation is final, it is possible to change its state when more information is available."""
        return self in {ValidationState.FULL, ValidationState.CHECKPOINT_FULL, ValidationState.INVALID}

    @classmethod
    def from_name(cls, name: str) -> 'ValidationState':
        value = getattr(cls, name.upper(), None)
        if value is None:
            raise ValueError('invalid name')
        return value


class TransactionMetadata:
    hash: Optional[bytes]
    spent_outputs: Dict[int, List[bytes]]
    # XXX: the following Optional[] types use None to replace empty set/list to reduce memory use
    conflict_with: Optional[List[bytes]]
    voided_by: Optional[Set[bytes]]
    received_by: List[int]
    children: List[bytes]
    twins: List[bytes]
    accumulated_weight: float
    score: float
    first_block: Optional[bytes]
    height: int
    validation: ValidationState

    # It must be a weakref.
    _tx_ref: Optional['ReferenceType[BaseTransaction]']

    # Used to detect changes in voided_by.
    _last_voided_by_hash: Optional[int]
    _last_spent_by_hash: Optional[int]

    def __init__(self, spent_outputs: Optional[Dict[int, List[bytes]]] = None, hash: Optional[bytes] = None,
                 accumulated_weight: float = 0, score: float = 0, height: int = 0) -> None:
        from hathor.transaction.genesis import is_genesis

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

        # Hash of the transactions that void this transaction.
        #
        # When a transaction has a conflict and is voided because of this conflict, its own hash is added to
        # voided_by. The logic is that the transaction is voiding itself.
        #
        # When a block is voided, its own hash is added to voided_by.
        self.voided_by = None
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

        # Validation
        self.validation = ValidationState.INITIAL

        # Genesis specific:
        if hash is not None and is_genesis(hash):
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
                      'children', 'accumulated_weight', 'twins', 'score',
                      'first_block', 'validation']:
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

    def to_json(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
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
        if self.first_block is not None:
            data['first_block'] = self.first_block.hex()
        else:
            data['first_block'] = None
        data['validation'] = self.validation.name.lower()
        return data

    @classmethod
    def create_from_json(cls, data: Dict[str, Any]) -> 'TransactionMetadata':
        from hathor.transaction.genesis import is_genesis

        meta = cls()
        meta.hash = bytes.fromhex(data['hash']) if data['hash'] else None
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

        first_block_raw = data.get('first_block', None)
        if first_block_raw:
            meta.first_block = bytes.fromhex(first_block_raw)

        _val_name = data.get('validation', None)
        meta.validation = ValidationState.from_name(_val_name) if _val_name is not None else ValidationState.INITIAL

        if meta.hash is not None and is_genesis(meta.hash):
            meta.validation = ValidationState.FULL

        return meta

    def clone(self) -> 'TransactionMetadata':
        """Return exact copy without sharing memory.

        :return: TransactionMetadata
        :rtype: :py:class:`hathor.transaction.TransactionMetadata`
        """
        # XXX: using json serialization for simplicity, should it use pickle? manual fields? other alternative?
        return self.create_from_json(self.to_json())
