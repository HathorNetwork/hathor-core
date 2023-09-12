#  Copyright 2023 Hathor Labs
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

from typing import Optional

from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_description import FeatureDescription
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction import Block, Transaction
from hathor.transaction.storage import TransactionStorage


class FeatureService:
    __slots__ = ('_feature_settings', '_avg_time_between_blocks', '_tx_storage')

    def __init__(self, *, settings: HathorSettings, tx_storage: TransactionStorage) -> None:
        self._feature_settings = settings.FEATURE_ACTIVATION
        self._avg_time_between_blocks = settings.AVG_TIME_BETWEEN_BLOCKS
        self._tx_storage = tx_storage

    def is_feature_active_for_block(self, *, block: Block, feature: Feature) -> bool:
        """Returns whether a Feature is active at a certain block."""
        state = self.get_state(block=block, feature=feature)

        return state == FeatureState.ACTIVE

    def is_feature_active_for_transaction(self, *, transaction: Transaction, feature: Feature) -> bool:
        current_best_block = self._tx_storage.get_best_block()
        first_active_boundary_block = self._get_first_active_block(current_best_block, feature)

        if not first_active_boundary_block:
            return False

        avg_time_between_boundaries = self._feature_settings.evaluation_interval * self._avg_time_between_blocks
        expected_second_active_boundary_timestamp = first_active_boundary_block.timestamp + avg_time_between_boundaries
        assert transaction.timestamp is not None
        is_active = transaction.timestamp >= expected_second_active_boundary_timestamp

        return is_active

    def _get_first_active_block(self, block: Block, feature: Feature) -> Optional[Block]:
        if not self.is_feature_active_for_block(block=block, feature=feature):
            return None

        parent = block.get_block_parent()
        parent_state = self.get_state(block=parent, feature=feature)

        if parent_state is FeatureState.LOCKED_IN:
            return block

        height = block.get_height()
        offset_to_boundary = height % self._feature_settings.evaluation_interval
        offset_to_previous_boundary = offset_to_boundary or self._feature_settings.evaluation_interval
        previous_boundary_height = height - offset_to_previous_boundary
        previous_boundary_block = self._get_ancestor_at_height(block=block, height=previous_boundary_height)

        return self._get_first_active_block(previous_boundary_block, feature)

    """

    block_ac_0
    block_ac_1
    block_ac_2

    if tx.timestamp >= block_ac_2.timestamp:
        if best_block >= block_ac_1:
            ret ACTIVE

        if tx.timestamp >= block_ac_3.timestamp:
            if best_block >= block_ac_2:
                ret ACTIVE

            if tx.timestamp >= block_ac_4.timestamp:
                if best_block >= block_ac_3:
                    ret ACTIVE

                raise

    ret INACTIVE

    """

    """
    current best block tem q ter height maior que o EB anterior ao expected closest EB
    """

    """

    never reorg 40.320/2 blocks (either exit or soft CP)

    tx is active if tx.timestamp >= block_ac_2.timestamp
        and current_best_block >= block_ac_1

        ... and use density? use 40.320/2 between current_best_block and block_ac_1? WHAT FUCK

    """

    """

    ac_0
    expected_ac_1_timestamp
    expected_ac_2_timestamp

    tx is active if tx.timestamp >= expected_ac_2_timestamp

    on expected_ac_1_timestamp, ac_0 becomes a soft CP
        IF


    """

    """

    tx is active if tx.timestamp >= expected_ac_1_timestamp

    problema: um reorg muda o ac_0, e já passei do expected_ac_1_timestamp:

        se eu ja passei do expected_ac_1_timestamp, e o reorg TIRA o ac_0, ele é INVALIDO
        se eu ja passei do expected_ac_1_timestamp, e o reorg coloca um new_ac_0 com
            new_ac_0.timestamp >= expected_ac_1_timestamp, ele é INVALIDO

    """

    def get_state(self, *, block: Block, feature: Feature) -> FeatureState:
        """Returns the state of a feature at a certain block. Uses block metadata to cache states."""

        # per definition, the genesis block is in the DEFINED state for all features
        if block.is_genesis:
            return FeatureState.DEFINED

        if state := block.get_feature_state(feature=feature):
            return state

        # All blocks within the same evaluation interval have the same state, that is, the state is only defined for
        # the block in each interval boundary. Therefore, we get the state of the previous boundary block or calculate
        # a new state if this block is a boundary block.
        height = block.get_height()
        offset_to_boundary = height % self._feature_settings.evaluation_interval
        offset_to_previous_boundary = offset_to_boundary or self._feature_settings.evaluation_interval
        previous_boundary_height = height - offset_to_previous_boundary
        assert previous_boundary_height >= 0
        previous_boundary_block = self._get_ancestor_at_height(block=block, height=previous_boundary_height)
        previous_boundary_state = self.get_state(block=previous_boundary_block, feature=feature)

        if offset_to_boundary != 0:
            return previous_boundary_state

        new_state = self._calculate_new_state(
            boundary_block=block,
            feature=feature,
            previous_state=previous_boundary_state
        )

        block.update_feature_state(feature=feature, state=new_state)

        return new_state

    def _calculate_new_state(
        self,
        *,
        boundary_block: Block,
        feature: Feature,
        previous_state: FeatureState
    ) -> FeatureState:
        """
        Returns the new feature state based on the new boundary block, the criteria, and the previous state.

        This method must only be called for boundary blocks, and calling it with a non-boundary block will raise
        an AssertionError. Non-boundary blocks never calculate their own state, they get it from their parent block
        instead.
        """
        height = boundary_block.get_height()
        criteria = self._feature_settings.features.get(feature)
        evaluation_interval = self._feature_settings.evaluation_interval

        if not criteria:
            return FeatureState.DEFINED

        assert not boundary_block.is_genesis, 'cannot calculate new state for genesis'
        assert height % evaluation_interval == 0, 'cannot calculate new state for a non-boundary block'

        if previous_state is FeatureState.DEFINED:
            if height >= criteria.start_height:
                return FeatureState.STARTED

            return FeatureState.DEFINED

        if previous_state is FeatureState.STARTED:
            if height >= criteria.timeout_height and not criteria.lock_in_on_timeout:
                return FeatureState.FAILED

            # Get the count for this block's parent. Since this is a boundary block, its parent count represents the
            # previous evaluation interval count.
            parent_block = boundary_block.get_block_parent()
            counts = parent_block.get_feature_activation_bit_counts()
            count = counts[criteria.bit]
            threshold = criteria.get_threshold(self._feature_settings)

            if height < criteria.timeout_height and count >= threshold:
                return FeatureState.LOCKED_IN

            if (height + evaluation_interval >= criteria.timeout_height) and criteria.lock_in_on_timeout:
                return FeatureState.MUST_SIGNAL

            return FeatureState.STARTED

        if previous_state is FeatureState.MUST_SIGNAL:
            # The MUST_SIGNAL state is defined to always take exactly one evaluation interval. Since this method is
            # only called for boundary blocks, it is guaranteed that after exactly one evaluation interval in
            # MUST_SIGNAL, the feature will transition to LOCKED_IN.
            return FeatureState.LOCKED_IN

        if previous_state is FeatureState.LOCKED_IN:
            if height >= criteria.minimum_activation_height:
                return FeatureState.ACTIVE

            return FeatureState.LOCKED_IN

        if previous_state is FeatureState.ACTIVE:
            return FeatureState.ACTIVE

        if previous_state is FeatureState.FAILED:
            return FeatureState.FAILED

        raise ValueError(f'Unknown previous state: {previous_state}')

    def get_bits_description(self, *, block: Block) -> dict[Feature, FeatureDescription]:
        """Returns the criteria definition and feature state for all features at a certain block."""
        return {
            feature: FeatureDescription(
                criteria=criteria,
                state=self.get_state(block=block, feature=feature)
            )
            for feature, criteria in self._feature_settings.features.items()
        }

    def _get_ancestor_at_height(self, *, block: Block, height: int) -> Block:
        """
        Given a block, returns its ancestor at a specific height.
        Uses the height index if the block is in the best blockchain, or search iteratively otherwise.
        """
        assert height < block.get_height(), (
            f"ancestor height must be lower than the block's height: {height} >= {block.get_height()}"
        )

        metadata = block.get_metadata()

        if not metadata.voided_by and (ancestor := self._tx_storage.get_transaction_by_height(height)):
            assert isinstance(ancestor, Block)
            return ancestor

        return _get_ancestor_iteratively(block=block, ancestor_height=height)

    def reorg_is_valid(self, *, common_block: Block, old_best_block: Block) -> bool:
        """
        se entre o common_block e o old_best_height NAO tem um EB:
            return False

        tem um ou mais EBs

        se NENHUM EB é um first_active_EB:
            reutrn False

        algum é um first_active_EB

        se old_best_tip.timestamp < expected_ac_1_timestamp
            return False

        eu ja tinha chegado no expected_ac_1_timestamp, talvez tenham txs q usaram o active

        return True
        """
        common_height = common_block.get_height()
        old_best_height = old_best_block.get_height()

        affected_boundary_heights = self._get_affected_boundary_heights(
            common_height=common_height,
            old_best_height=old_best_height
        )

        if not affected_boundary_heights:
            return True

        first_active_boundary_blocks = self._get_first_active_boundary_blocks(
            common_block=common_block,
            boundary_heights=affected_boundary_heights
        )

        if not first_active_boundary_blocks:
            return True

        old_best_block_is_after_second_active_boundary = self._old_best_block_is_after_second_active_boundary(
            first_active_boundary_blocks=first_active_boundary_blocks,
            old_best_block=old_best_block
        )

        if not old_best_block_is_after_second_active_boundary:
            return True

        # TODO: self.log.critical()
        return False

    def _get_affected_boundary_heights(self, *, common_height: int, old_best_height: int) -> set[int]:
        affected_boundary_heights = set()

        for height in range(common_height + 1, old_best_height + 1):
            if height % self._feature_settings.evaluation_interval == 0:
                affected_boundary_heights.add(height)

        return affected_boundary_heights

    def _get_first_active_boundary_blocks(self, *, common_block: Block, boundary_heights: set[int]) -> set[Block]:
        first_active_boundary_blocks = set()

        for height in boundary_heights:
            block = self._get_ancestor_at_height(block=common_block, height=height)

            if self._is_first_active_boundary_block(boundary_block=block):
                first_active_boundary_blocks.add(block)

        return first_active_boundary_blocks

    def _is_first_active_boundary_block(self, *, boundary_block: Block) -> bool:
        assert boundary_block.get_height() % self._feature_settings.evaluation_interval == 0
        descriptions = self.get_bits_description(block=boundary_block)

        for feature, description in descriptions:
            if description.state is not FeatureState.ACTIVE:
                continue

            parent = boundary_block.get_block_parent()
            parent_descriptions = self.get_bits_description(block=parent)
            parent_state = parent_descriptions[feature].state

            if parent_state is FeatureState.LOCKED_IN:
                return True

        return False

    def _old_best_block_is_after_second_active_boundary(
        self,
        *,
        first_active_boundary_blocks: set[Block],
        old_best_block: Block
    ) -> bool:
        avg_time_between_boundaries = self._feature_settings.evaluation_interval * self._avg_time_between_blocks

        # TODO: Merge logic with is_feature_active_for_transaction
        for first_active_boundary_block in first_active_boundary_blocks:
            assert self._is_first_active_boundary_block(boundary_block=first_active_boundary_block)
            expected_second_active_boundary_timestamp = (
                first_active_boundary_block.timestamp + avg_time_between_boundaries
            )

            if expected_second_active_boundary_timestamp <= old_best_block.timestamp:
                return True

        return False


def _get_ancestor_iteratively(*, block: Block, ancestor_height: int) -> Block:
    """Given a block, returns its ancestor at a specific height by iterating over its ancestors. This is slow."""
    # TODO: there are further optimizations to be done here, the latest common block height could be persisted in
    #  metadata, so we could still use the height index if the requested height is before that height.
    assert ancestor_height >= 0
    ancestor = block
    while ancestor.get_height() > ancestor_height:
        ancestor = ancestor.get_block_parent()

    return ancestor
