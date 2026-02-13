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
from typing import TYPE_CHECKING, Any, Iterator, Optional

from typing_extensions import Self, override

from hathor.checkpoint import Checkpoint
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.serialization import Serializer
from hathor.transaction import TxOutput, TxVersion
from hathor.transaction.base_transaction import GenericVertex
from hathor.transaction.exceptions import CheckpointError
from hathor.transaction.static_metadata import BlockStaticMetadata
from hathor.transaction.util import VerboseCallback
from hathor.utils.int import get_bit_list

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import Transaction
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


class Block(GenericVertex[BlockStaticMetadata]):
    SERIALIZATION_NONCE_SIZE = 16

    def __init__(
        self,
        nonce: int = 0,
        timestamp: Optional[int] = None,
        signal_bits: int = 0,
        version: TxVersion = TxVersion.REGULAR_BLOCK,
        weight: float = 0,
        outputs: Optional[list[TxOutput]] = None,
        parents: Optional[list[bytes]] = None,
        hash: Optional[bytes] = None,
        data: bytes = b'',
        storage: Optional['TransactionStorage'] = None,
        settings: HathorSettings | None = None,
    ) -> None:
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            signal_bits=signal_bits,
            version=version,
            weight=weight,
            outputs=outputs or [],
            parents=parents or [],
            hash=hash,
            storage=storage,
            settings=settings,
        )
        self.data = data

    def _get_formatted_fields_dict(self, short: bool = True) -> dict[str, str]:
        d = super()._get_formatted_fields_dict(short)
        if not short:
            d.update(data=self.data.hex())
        return d

    @override
    def get_funds_struct(self) -> bytes:
        from hathor.transaction.vertex_parser._block import serialize_block_funds
        serializer = Serializer.build_bytes_serializer()
        serialize_block_funds(serializer, self)
        return bytes(serializer.finalize())

    @override
    def get_graph_struct(self) -> bytes:
        from hathor.transaction.vertex_parser._block import serialize_block_graph_fields
        serializer = Serializer.build_bytes_serializer()
        serialize_block_graph_fields(serializer, self)
        return bytes(serializer.finalize())

    @classmethod
    @override
    def create_from_struct(cls, struct_bytes: bytes, storage: Optional['TransactionStorage'] = None,
                           *, verbose: VerboseCallback = None) -> Self:
        from hathor.conf.get_settings import get_global_settings
        from hathor.serialization import Deserializer
        from hathor.transaction.vertex_parser._block import deserialize_block_funds, deserialize_block_graph_fields
        from hathor.transaction.vertex_parser._headers import deserialize_headers
        settings = get_global_settings()
        block = cls(storage=storage)
        deserializer = Deserializer.build_bytes_deserializer(struct_bytes)
        deserialize_block_funds(deserializer, block, verbose=verbose)
        deserialize_block_graph_fields(deserializer, block, verbose=verbose)
        block.nonce = int.from_bytes(deserializer.read_bytes(cls.SERIALIZATION_NONCE_SIZE), byteorder='big')
        deserialize_headers(deserializer, block, settings)
        deserializer.finalize()
        block.update_hash()
        if storage is not None:
            block.storage = storage
        return block

    @property
    def is_block(self) -> bool:
        """Returns true if this is a block"""
        return True

    @property
    def is_transaction(self) -> bool:
        """Returns true if this is a transaction"""
        return False

    def get_next_block_best_chain_hash(self) -> Optional[bytes]:
        """Return the hash of the next block in the best blockchain. The blockchain is
        written from left-to-righ (->), meaning the next block has a greater height.
        In a timeline, the parent block (left) comes first of the child (right).

             +-----------+       +-----------+       +-----------+
         --->| height: 1 |------>| height: 2 |------>| height: 3 |--->
             |  parent   |       |  current  |       |   child   |
             +-----------+       +-----------+       +-----------+
                 left                                    right
                 past                                   future

                                "left-to-right"
        """
        assert self.storage is not None
        meta = self.get_metadata()
        assert not meta.voided_by

        candidates = []
        for h in self.get_children():
            blk = self.storage.get_transaction(h)
            assert blk.is_block
            blk_meta = blk.get_metadata()
            if blk_meta.voided_by:
                continue
            candidates.append(h)

        if len(candidates) == 0:
            return None
        assert len(candidates) == 1
        return candidates[0]

    def get_next_block_best_chain(self) -> Optional['Block']:
        """Return the next block in the best blockchain. The blockchain is written
        from left-to-righ (->), meaning the next block has a greater height.
        In a timeline, the parent block (left) comes first of the child (right).

             +-----------+       +-----------+       +-----------+
         --->| height: 1 |------>| height: 2 |------>| height: 3 |--->
             |  parent   |       |  current  |       |   child   |
             +-----------+       +-----------+       +-----------+
                 left                                    right
                 past                                   future

                                "left-to-right"
        """
        assert self.storage is not None
        h = self.get_next_block_best_chain_hash()
        if h is None:
            return None
        tx = self.storage.get_transaction(h)
        assert isinstance(tx, Block)
        return tx

    def get_block_parent_hash(self) -> bytes:
        """ Return the hash of the parent block.
        """
        return self.parents[0]

    def get_block_parent(self) -> 'Block':
        """Return the parent block.
        """
        assert self.storage is not None
        block_parent = self.storage.get_transaction(self.get_block_parent_hash())
        assert isinstance(block_parent, Block)
        return block_parent

    def get_token_uid(self, index: int) -> bytes:
        """Returns the token uid with corresponding index from the tx token uid list.

        Blocks can only have HTR tokens

        :param index: token index on the token uid list
        :type index: int

        :return: the token uid
        :rtype: bytes
        """
        assert index == 0
        return self._settings.HATHOR_TOKEN_UID

    # TODO: maybe introduce convention on serialization methods names (e.g. to_json vs get_struct)
    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['tokens'] = []
        json['data'] = base64.b64encode(self.data).decode('utf-8')
        return json

    def to_json_extended(self) -> dict[str, Any]:
        json = super().to_json_extended()
        json['height'] = self.static_metadata.height

        return json

    def has_basic_block_parent(self) -> bool:
        """Whether all block parent is in storage and is at least basic-valid."""
        assert self.storage is not None
        parent_block_hash = self.parents[0]
        if not self.storage.transaction_exists(parent_block_hash):
            return False
        metadata = self.storage.get_metadata(parent_block_hash)
        if metadata is None:
            return False
        return metadata.validation.is_at_least_basic()

    def verify_checkpoint(self, checkpoints: list[Checkpoint]) -> None:
        assert self.hash is not None
        assert self.storage is not None
        height = self.get_height()  # TODO: use "soft height" when sync-checkpoint is added
        # find checkpoint with our height:
        checkpoint: Optional[Checkpoint] = None
        for cp in checkpoints:
            if cp.height == height:
                checkpoint = cp
                break
        if checkpoint is not None and checkpoint.hash != self.hash:
            raise CheckpointError(f'Invalid new block {self.hash_hex}: checkpoint hash does not match')
        else:
            # TODO: check whether self is a parent of any checkpoint-valid block, this is left for a future PR
            pass

    def get_mining_base_hash(self) -> bytes:
        from hathor.merged_mining.bitcoin import sha256d_hash
        return sha256d_hash(self.get_mining_header_without_nonce())

    def get_height(self) -> int:
        """Return this block's height."""
        return self.static_metadata.height

    def _get_feature_activation_bit_list(self) -> list[int]:
        """
        Extracts feature activation bits from the signal bits, as a list where each index corresponds to the bit
        position. LSB is on the left.
        """
        assert self.signal_bits <= 0xFF, 'signal_bits must be one byte at most'

        bitmask = self._get_feature_activation_bitmask()
        bits = self.signal_bits & bitmask

        bit_list = get_bit_list(bits, min_size=self._settings.FEATURE_ACTIVATION.max_signal_bits)

        return bit_list

    def _get_feature_activation_bitmask(self) -> int:
        """Returns the bitmask that gets feature activation bits from signal bits."""
        bitmask = (1 << self._settings.FEATURE_ACTIVATION.max_signal_bits) - 1

        return bitmask

    def get_feature_state(self, *, feature: Feature) -> Optional[FeatureState]:
        """Returns the state of a feature from metadata."""
        metadata = self.get_metadata()
        feature_states = metadata.feature_states or {}

        return feature_states.get(feature)

    def set_feature_state(self, *, feature: Feature, state: FeatureState, save: bool = False) -> None:
        """
        Set the state of a feature in metadata, if it's not set. Fails if it's set and the value is different.

        Args:
            feature: the feature to set the state of.
            state: the state to set.
            save: whether to save this block's metadata in storage.
        """
        previous_state = self.get_feature_state(feature=feature)

        if state != previous_state:
            # we are settings the state for the first time in this block
            assert previous_state is None
            metadata = self.get_metadata()
            feature_states = metadata.feature_states or {}
            feature_states[feature] = state
            metadata.feature_states = feature_states

        if save:
            assert self.storage is not None
            self.storage.save_transaction(self, only_metadata=True)

    def get_feature_activation_bit_value(self, bit: int) -> int:
        """Get the feature activation bit value for a specific bit position."""
        bit_list = self._get_feature_activation_bit_list()

        return bit_list[bit]

    def iter_transactions_in_this_block(self) -> Iterator[Transaction]:
        """Return an iterator of the transactions that have this block as meta.first_block."""
        from hathor.transaction import Transaction
        from hathor.transaction.storage.traversal import BFSOrderWalk
        assert self.storage is not None
        bfs = BFSOrderWalk(self.storage, is_dag_verifications=True, is_dag_funds=True, is_left_to_right=False)
        for tx in bfs.run(self, skip_root=True):
            tx_meta = tx.get_metadata()
            if tx_meta.first_block != self.hash:
                bfs.skip_neighbors()
                continue
            assert isinstance(tx, Transaction)
            yield tx
            bfs.add_neighbors()

    @override
    def init_static_metadata_from_storage(self, settings: HathorSettings, storage: 'TransactionStorage') -> None:
        static_metadata = BlockStaticMetadata.create_from_storage(self, settings, storage)
        self.set_static_metadata(static_metadata)
