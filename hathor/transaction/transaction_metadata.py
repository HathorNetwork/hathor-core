"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from hathor import protos
from hathor.util import practically_equal

if TYPE_CHECKING:
    from weakref import ReferenceType  # noqa: F401

    from hathor.transaction import BaseTransaction  # noqa: F401


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

    # It must be a weakref.
    _tx_ref: Optional['ReferenceType[BaseTransaction]']

    # Used to detect changes in voided_by.
    _last_voided_by_hash: Optional[int]
    _last_spent_by_hash: Optional[int]

    def __init__(self, spent_outputs: Optional[Dict[int, List[bytes]]] = None, hash: Optional[bytes] = None,
                 accumulated_weight: float = 0, score: float = 0, height: int = 0) -> None:

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
                      'first_block']:
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
        data['conflict_with'] = [x.hex() for x in self.conflict_with] if self.conflict_with else []
        data['voided_by'] = [x.hex() for x in self.voided_by] if self.voided_by else []
        data['twins'] = [x.hex() for x in self.twins]
        data['accumulated_weight'] = self.accumulated_weight
        data['score'] = self.score
        data['height'] = self.height
        if self.first_block is not None:
            data['first_block'] = self.first_block.hex()
        else:
            data['first_block'] = None
        return data

    @classmethod
    def create_from_json(cls, data: Dict[str, Any]) -> 'TransactionMetadata':
        meta = cls()
        meta.hash = bytes.fromhex(data['hash']) if data['hash'] else None
        for idx, hashes in data['spent_outputs']:
            for h_hex in hashes:
                meta.spent_outputs[idx].append(bytes.fromhex(h_hex))
        meta.received_by = list(data['received_by'])
        meta.children = [bytes.fromhex(h) for h in data['children']]

        if 'conflict_with' in data:
            meta.conflict_with = [bytes.fromhex(h) for h in data['conflict_with']] if data['conflict_with'] else None
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

        return meta

    # XXX(jansegre): I did not put the transaction hash in the protobuf object to keep it less redundant. Is this OK?
    @classmethod
    def create_from_proto(cls, hash_bytes: bytes, metadata_proto: protos.Metadata) -> 'TransactionMetadata':
        """ Create a TransactionMetadata from a protobuf Metadata object.

        :param hash_bytes: hash of the transaction in bytes
        :type hash_bytes: bytes

        :param metadata_proto: Protobuf transaction object
        :type metadata_proto: :py:class:`hathor.protos.Metadata`

        :return: A transaction metadata
        :rtype: TransactionMetadata
        """
        metadata = cls(hash=hash_bytes)
        for i, hashes in metadata_proto.spent_outputs.items():
            metadata.spent_outputs[i] = list(hashes.hashes)
        metadata.conflict_with = list(metadata_proto.conflicts_with.hashes) or None
        metadata.voided_by = set(metadata_proto.voided_by.hashes) or None
        metadata.twins = list(metadata_proto.twins.hashes)
        metadata.received_by = list(metadata_proto.received_by)
        metadata.children = list(metadata_proto.children.hashes)
        metadata.accumulated_weight = metadata_proto.accumulated_weight
        metadata.score = metadata_proto.score
        metadata.first_block = metadata_proto.first_block or None
        metadata.height = metadata_proto.height
        return metadata

    def to_proto(self) -> protos.Metadata:
        """ Creates a Probuf object from self

        :return: Protobuf object
        :rtype: :py:class:`hathor.protos.Metadata`
        """
        from hathor import protos
        return protos.Metadata(
            spent_outputs={k: protos.Metadata.Hashes(hashes=v)
                           for k, v in self.spent_outputs.items()},
            conflicts_with=protos.Metadata.Hashes(hashes=self.conflict_with),
            voided_by=protos.Metadata.Hashes(hashes=self.voided_by),
            twins=protos.Metadata.Hashes(hashes=self.twins),
            received_by=self.received_by,
            children=protos.Metadata.Hashes(hashes=self.children),
            accumulated_weight=self.accumulated_weight,
            score=self.score,
            first_block=self.first_block,
            height=self.height,
        )

    def clone(self) -> 'TransactionMetadata':
        """Return exact copy without sharing memory.

        :return: TransactionMetadata
        :rtype: :py:class:`hathor.transaction.TransactionMetadata`
        """
        # XXX: using json serialization for simplicity, should it use pickle? manual fields? other alternative?
        return self.create_from_json(self.to_json())
