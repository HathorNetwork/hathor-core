#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from abc import ABC
from itertools import chain, starmap, zip_longest
from operator import add
from typing import TYPE_CHECKING, Callable

from typing_extensions import Self, override

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.types import VertexId
from hathor.util import json_loadb
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import BaseTransaction, Block, Transaction
    from hathor.transaction.storage import TransactionStorage


class VertexStaticMetadata(ABC, BaseModel):
    """
    Static Metadata represents vertex attributes that are not intrinsic to the vertex data, but can be calculated from
    only the vertex itself and its dependencies, and whose values never change.

    This class is an abstract base class for all static metadata types that includes attributes common to all vertex
    types.
    """

    # XXX: this is only used to defer the reward-lock verification from the transaction spending a reward to the first
    # block that confirming this transaction, it is important to always have this set to be able to distinguish an old
    # metadata (that does not have this calculated, from a tx with a new format that does have this calculated)
    min_height: int

    @classmethod
    def from_bytes(cls, data: bytes, *, target: 'BaseTransaction') -> 'VertexStaticMetadata':
        """Create a static metadata instance from a json bytes representation, with a known vertex type target."""
        from hathor.transaction import Block, Transaction
        json_dict = json_loadb(data)

        if isinstance(target, Block):
            return BlockStaticMetadata(**json_dict)

        if isinstance(target, Transaction):
            json_dict['closest_ancestor_block'] = bytes.fromhex(json_dict['closest_ancestor_block'])
            return TransactionStaticMetadata(**json_dict)

        raise NotImplementedError


class BlockStaticMetadata(VertexStaticMetadata):
    height: int

    # A list of feature activation bit counts.
    # Each list index corresponds to a bit position, and its respective value is the rolling count of active bits from
    # the previous boundary block up to this block, including it. LSB is on the left.
    feature_activation_bit_counts: list[int]

    # A dict of features in the feature activation process and their respective state.
    feature_states: dict[Feature, FeatureState]

    # Score represents the accumulated work (proof-of-work) from genesis to this block
    score: int

    @classmethod
    def create_from_storage(cls, block: 'Block', settings: HathorSettings, storage: 'TransactionStorage') -> Self:
        """Create a `BlockStaticMetadata` using dependencies provided by a storage."""
        return cls.create(block, settings, storage.get_vertex)

    @classmethod
    def create(
        cls,
        block: 'Block',
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'BaseTransaction']
    ) -> Self:
        """Create a `BlockStaticMetadata` using dependencies provided by a `vertex_getter`.
        This must be fast, ideally O(1)."""
        height = cls._calculate_height(block, vertex_getter)
        min_height = cls._calculate_min_height(block, vertex_getter)
        feature_activation_bit_counts = cls._calculate_feature_activation_bit_counts(
            block,
            height,
            settings,
            vertex_getter,
        )
        score = cls._calculate_score(block, vertex_getter)

        return cls(
            height=height,
            min_height=min_height,
            feature_activation_bit_counts=feature_activation_bit_counts,
            feature_states={},  # This will be populated in a future PR, it's currently still in normal metadata
            score=score,
        )

    @staticmethod
    def _calculate_height(block: 'Block', vertex_getter: Callable[[VertexId], 'BaseTransaction']) -> int:
        """Return the height of the block, i.e., the number of blocks since genesis"""
        if block.is_genesis:
            return 0

        from hathor.transaction import Block
        parent_hash = block.get_block_parent_hash()
        parent_block = vertex_getter(parent_hash)
        assert isinstance(parent_block, Block)
        return parent_block.static_metadata.height + 1

    @staticmethod
    def _calculate_min_height(block: 'Block', vertex_getter: Callable[[VertexId], 'BaseTransaction']) -> int:
        """The minimum height the next block needs to have, basically the maximum min-height of this block's parents.
        """
        # maximum min-height of any parent tx
        min_height = 0
        for tx_hash in block.get_tx_parents_ids():
            tx = vertex_getter(tx_hash)
            min_height = max(min_height, tx.static_metadata.min_height)

        return min_height

    @classmethod
    def _calculate_feature_activation_bit_counts(
        cls,
        block: 'Block',
        height: int,
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'BaseTransaction'],
    ) -> list[int]:
        """
        Lazily calculates the feature_activation_bit_counts metadata attribute, which is a list of feature activation
        bit counts. After it's calculated for the first time, it's persisted in block metadata and must not be changed.

        Each list index corresponds to a bit position, and its respective value is the rolling count of active bits
        from the previous boundary block up to this block, including it. LSB is on the left.
        """
        previous_counts = cls._get_previous_feature_activation_bit_counts(block, height, settings, vertex_getter)
        bit_list = block._get_feature_activation_bit_list()

        count_and_bit_pairs = zip_longest(previous_counts, bit_list, fillvalue=0)
        updated_counts = starmap(add, count_and_bit_pairs)
        return list(updated_counts)

    @staticmethod
    def _get_previous_feature_activation_bit_counts(
        block: 'Block',
        height: int,
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'BaseTransaction'],
    ) -> list[int]:
        """
        Returns the feature_activation_bit_counts metadata attribute from the parent block,
        or no previous counts if this is a boundary block.
        """
        evaluation_interval = settings.FEATURE_ACTIVATION.evaluation_interval
        is_boundary_block = height % evaluation_interval == 0

        if is_boundary_block:
            return []

        from hathor.transaction import Block
        parent_hash = block.get_block_parent_hash()
        parent_block = vertex_getter(parent_hash)
        assert isinstance(parent_block, Block)

        return parent_block.static_metadata.feature_activation_bit_counts

    @staticmethod
    def _calculate_score(block: 'Block', vertex_getter: Callable[[VertexId], 'BaseTransaction']) -> int:
        """Calculate the score as parent_score + weight_to_work(block.weight).

        Score represents the accumulated work (proof-of-work) from genesis to this block.
        For genesis blocks, score equals the block's own weight.
        For other blocks, score is the parent block's score plus this block's weight.
        """
        from hathor.utils.weight import weight_to_work

        if block.is_genesis:
            return weight_to_work(block.weight)

        from hathor.transaction import Block
        parent_hash = block.get_block_parent_hash()
        parent_block = vertex_getter(parent_hash)
        assert isinstance(parent_block, Block)
        return parent_block.static_metadata.score + weight_to_work(block.weight)


class TransactionStaticMetadata(VertexStaticMetadata):
    # The Block with the greatest height that is a direct or indirect dependency (ancestor) of the transaction,
    # including both funds and verification DAGs. It's used by Feature Activation for Transactions.
    closest_ancestor_block: VertexId

    @classmethod
    def create_from_storage(cls, tx: 'Transaction', settings: HathorSettings, storage: 'TransactionStorage') -> Self:
        """Create a `TransactionStaticMetadata` using dependencies provided by a storage."""
        return cls.create(tx, settings, storage.get_vertex)

    @classmethod
    def create(
        cls,
        tx: 'Transaction',
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'BaseTransaction'],
    ) -> Self:
        """Create a `TransactionStaticMetadata` using dependencies provided by a `vertex_getter`.
        This must be fast, ideally O(1)."""
        min_height = cls._calculate_min_height(tx, settings, vertex_getter)
        closest_ancestor_block = cls._calculate_closest_ancestor_block(tx, settings, vertex_getter)

        return cls(
            min_height=min_height,
            closest_ancestor_block=closest_ancestor_block,
        )

    @classmethod
    def _calculate_min_height(
        cls,
        tx: 'Transaction',
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'BaseTransaction'],
    ) -> int:
        """Calculates the min height the first block confirming this tx needs to have for reward lock verification."""
        if tx.is_genesis:
            return 0

        return max(
            # 1) don't drop the min height of any parent tx or input tx
            cls._calculate_inherited_min_height(tx, vertex_getter),
            # 2) include the min height for any reward being spent
            cls._calculate_my_min_height(tx, settings, vertex_getter),
        )

    @staticmethod
    def _calculate_inherited_min_height(
        tx: 'Transaction',
        vertex_getter: Callable[[VertexId], 'BaseTransaction']
    ) -> int:
        """ Calculates min height inherited from any input or parent"""
        min_height = 0
        iter_parents = tx.get_tx_parents_ids()
        iter_inputs = (tx_input.tx_id for tx_input in tx.inputs)
        for vertex_id in chain(iter_parents, iter_inputs):
            vertex = vertex_getter(vertex_id)
            min_height = max(min_height, vertex.static_metadata.min_height)
        return min_height

    @staticmethod
    def _calculate_my_min_height(
        tx: 'Transaction',
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'BaseTransaction'],
    ) -> int:
        """ Calculates min height derived from own spent block rewards"""
        from hathor.transaction import Block
        min_height = 0
        for tx_input in tx.inputs:
            spent_tx = vertex_getter(tx_input.tx_id)
            if isinstance(spent_tx, Block):
                min_height = max(min_height, spent_tx.static_metadata.height + settings.REWARD_SPEND_MIN_BLOCKS + 1)
        return min_height

    @staticmethod
    def _calculate_closest_ancestor_block(
        tx: 'Transaction',
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'BaseTransaction'],
    ) -> VertexId:
        """
        Calculate the tx's closest_ancestor_block. It's calculated by propagating the metadata forward in the DAG.
        """
        from hathor.transaction import Block, Transaction
        if tx.is_genesis:
            return settings.GENESIS_BLOCK_HASH

        closest_ancestor_block: Block | None = None

        for vertex_id in tx.get_all_dependencies():
            vertex = vertex_getter(vertex_id)
            candidate_block: Block

            if isinstance(vertex, Block):
                candidate_block = vertex
            elif isinstance(vertex, Transaction):
                vertex_candidate = vertex_getter(vertex.static_metadata.closest_ancestor_block)
                assert isinstance(vertex_candidate, Block)
                candidate_block = vertex_candidate
            else:
                raise NotImplementedError

            if (
                not closest_ancestor_block
                or candidate_block.static_metadata.height > closest_ancestor_block.static_metadata.height
            ):
                closest_ancestor_block = candidate_block

        assert closest_ancestor_block is not None
        return closest_ancestor_block.hash

    @override
    def json_dumpb(self) -> bytes:
        from hathor.util import json_dumpb
        json_dict = self.dict()
        json_dict['closest_ancestor_block'] = json_dict['closest_ancestor_block'].hex()
        return json_dumpb(json_dict)
