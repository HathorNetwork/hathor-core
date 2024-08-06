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
from typing import TYPE_CHECKING, Callable, Optional, TypeAlias

from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.transaction import Block, Vertex


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
    __slots__ = ('_feature_settings', '_vertex_getter', '_block_by_height_getter')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        vertex_getter: Callable[[VertexId], 'Vertex'],
        block_by_height_getter: Callable[[int], Optional['Block']],
    ) -> None:
        self._feature_settings = settings.FEATURE_ACTIVATION
        self._vertex_getter = vertex_getter
        self._block_by_height_getter = block_by_height_getter

    @staticmethod
    def is_signaling_mandatory_features(block: 'Block', settings: HathorSettings) -> BlockSignalingState:
        """
        Return whether a block is signaling features that are mandatory, that is, any feature currently in the
        MUST_SIGNAL phase.
        """
        feature_settings = settings.FEATURE_ACTIVATION
        bit_counts = block.static_metadata.feature_activation_bit_counts
        height = block.static_metadata.height
        offset_to_boundary = height % feature_settings.evaluation_interval
        remaining_blocks = feature_settings.evaluation_interval - offset_to_boundary - 1
        feature_infos = block.static_metadata.get_feature_infos(settings)

        must_signal_features = (
            feature for feature, feature_info in feature_infos.items()
            if feature_info.state is FeatureState.MUST_SIGNAL
        )

        for feature in must_signal_features:
            criteria = feature_settings.features[feature]
            threshold = criteria.get_threshold(feature_settings)
            count = bit_counts[criteria.bit]
            missing_signals = threshold - count

            if missing_signals > remaining_blocks:
                return BlockIsMissingSignal(feature=feature)

        return BlockIsSignaling()

    def calculate_all_feature_states(self, block: 'Block', *, height: int) -> dict[Feature, FeatureState]:
        """Calculate the state of all features at a certain block."""
        return {
            feature: self._calculate_state(block=block, height=height, feature=feature)
            for feature in self._feature_settings.features
        }

    def _calculate_state(self, *, block: 'Block', height: int, feature: Feature) -> FeatureState:
        """Calculate the state of a feature at a certain block."""

        # per definition, the genesis block is in the DEFINED state for all features
        if block.is_genesis:
            return FeatureState.DEFINED

        from hathor.transaction import Block
        parent_hash = block.get_block_parent_hash()
        parent_block = self._vertex_getter(parent_hash)
        assert isinstance(parent_block, Block)
        previous_state = parent_block.static_metadata.get_feature_state(feature)

        # All blocks within the same evaluation interval have the same state, that is, the state is only defined for
        # the block in each interval boundary. Therefore, we get the state of the previous block or calculate
        # a new state if this block is a boundary block.
        is_boundary_block = height % self._feature_settings.evaluation_interval == 0
        if not is_boundary_block:
            return previous_state

        return self._calculate_new_state(
            boundary_block=block,
            height=height,
            feature=feature,
            previous_state=previous_state
        )

    def _calculate_new_state(
        self,
        *,
        boundary_block: 'Block',
        height: int,
        feature: Feature,
        previous_state: FeatureState
    ) -> FeatureState:
        """
        Returns the new feature state based on the new boundary block, the criteria, and the previous state.

        This method must only be called for boundary blocks, and calling it with a non-boundary block will raise
        an AssertionError. Non-boundary blocks never calculate their own state, they get it from their parent block
        instead.
        """
        criteria = self._feature_settings.features.get(feature)
        evaluation_interval = self._feature_settings.evaluation_interval

        if not criteria:
            return FeatureState.DEFINED

        assert not boundary_block.is_genesis, 'cannot calculate new state for genesis'
        assert height % evaluation_interval == 0, 'cannot calculate new state for a non-boundary block'
        from hathor.transaction import Block

        if previous_state is FeatureState.DEFINED:
            if height >= criteria.start_height:
                return FeatureState.STARTED

            return FeatureState.DEFINED

        if previous_state is FeatureState.STARTED:
            if height >= criteria.timeout_height and not criteria.lock_in_on_timeout:
                return FeatureState.FAILED

            # Get the count for this block's parent. Since this is a boundary block, its parent count represents the
            # previous evaluation interval count.
            parent_block_hash = boundary_block.get_block_parent_hash()
            parent_block = self._vertex_getter(parent_block_hash)
            assert isinstance(parent_block, Block)
            counts = parent_block.static_metadata.feature_activation_bit_counts
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

        raise NotImplementedError(f'Unknown previous state: {previous_state}')
