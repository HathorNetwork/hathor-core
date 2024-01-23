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

from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_description import FeatureDescription
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.util import not_none

if TYPE_CHECKING:
    from hathor.transaction import Block, Transaction
    from hathor.transaction.storage import TransactionStorage


@dataclass(frozen=True, slots=True)
class BlockIsSignaling:
    """Represent that a block is correctly signaling support for all currently mandatory features."""
    pass


@dataclass(frozen=True, slots=True)
class BlockIsMissingSignal:
    """Represent that a block is not signaling support for at least one currently mandatory feature."""
    feature: Feature


BlockSignalingState: TypeAlias = BlockIsSignaling | BlockIsMissingSignal


class FeatureService:
    __slots__ = ('_feature_settings', '_tx_storage')

    def __init__(self, *, feature_settings: FeatureSettings, tx_storage: 'TransactionStorage') -> None:
        self._feature_settings = feature_settings
        self._tx_storage = tx_storage

    def is_feature_active_for_transaction(self, *, tx: 'Transaction', feature: Feature) -> bool:
        """Return whether a Feature is active for a certain Transaction."""
        metadata = tx.get_metadata()
        closest_block = self._tx_storage.get_block(not_none(metadata.closest_block))

        return self.is_feature_active_for_block(block=closest_block, feature=feature)

    def is_feature_active_for_block(self, *, block: 'Block', feature: Feature) -> bool:
        """Return whether a Feature is active for a certain block."""
        state = self.get_state(block=block, feature=feature)

        return state == FeatureState.ACTIVE

    def is_signaling_mandatory_features(self, block: 'Block') -> BlockSignalingState:
        """
        Return whether a block is signaling features that are mandatory, that is, any feature currently in the
        MUST_SIGNAL phase.
        """
        bit_counts = block.get_feature_activation_bit_counts()
        height = block.get_height()
        offset_to_boundary = height % self._feature_settings.evaluation_interval
        remaining_blocks = self._feature_settings.evaluation_interval - offset_to_boundary - 1
        descriptions = self.get_bits_description(block=block)

        must_signal_features = (
            feature for feature, description in descriptions.items()
            if description.state is FeatureState.MUST_SIGNAL
        )

        for feature in must_signal_features:
            criteria = self._feature_settings.features[feature]
            threshold = criteria.get_threshold(self._feature_settings)
            count = bit_counts[criteria.bit]
            missing_signals = threshold - count

            if missing_signals > remaining_blocks:
                return BlockIsMissingSignal(feature=feature)

        return BlockIsSignaling()

    def get_state(self, *, block: 'Block', feature: Feature) -> FeatureState:
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

        # We cache _and save_ the state of the previous boundary block that we just got.
        previous_boundary_block.set_feature_state(feature=feature, state=previous_boundary_state, save=True)

        if offset_to_boundary != 0:
            return previous_boundary_state

        new_state = self._calculate_new_state(
            boundary_block=block,
            feature=feature,
            previous_state=previous_boundary_state
        )

        # We cache the just calculated state of the current block _without saving it_, as it may still be unverified,
        # so we cannot persist its metadata. That's why we cache and save the previous boundary block above.
        block.set_feature_state(feature=feature, state=new_state)

        return new_state

    def _calculate_new_state(
        self,
        *,
        boundary_block: 'Block',
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

    def get_bits_description(self, *, block: 'Block') -> dict[Feature, FeatureDescription]:
        """Returns the criteria definition and feature state for all features at a certain block."""
        return {
            feature: FeatureDescription(
                criteria=criteria,
                state=self.get_state(block=block, feature=feature)
            )
            for feature, criteria in self._feature_settings.features.items()
        }

    def _get_ancestor_at_height(self, *, block: 'Block', height: int) -> 'Block':
        """
        Given a block, returns its ancestor at a specific height.
        Uses the height index if the block is in the best blockchain, or search iteratively otherwise.
        """
        assert height < block.get_height(), (
            f"ancestor height must be lower than the block's height: {height} >= {block.get_height()}"
        )

        metadata = block.get_metadata()

        if not metadata.voided_by and (ancestor := self._tx_storage.get_transaction_by_height(height)):
            from hathor.transaction import Block
            assert isinstance(ancestor, Block)
            return ancestor

        return _get_ancestor_iteratively(block=block, ancestor_height=height)


def _get_ancestor_iteratively(*, block: 'Block', ancestor_height: int) -> 'Block':
    """Given a block, returns its ancestor at a specific height by iterating over its ancestors. This is slow."""
    # TODO: there are further optimizations to be done here, the latest common block height could be persisted in
    #  metadata, so we could still use the height index if the requested height is before that height.
    assert ancestor_height >= 0
    ancestor = block
    while ancestor.get_height() > ancestor_height:
        ancestor = ancestor.get_block_parent()

    return ancestor
