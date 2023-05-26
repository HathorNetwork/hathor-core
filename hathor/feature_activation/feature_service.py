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

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_description import FeatureDescription
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings
from hathor.transaction import Block


class FeatureService:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: Settings) -> None:
        self._settings = settings

    def is_feature_active(self, *, block: Block, feature: Feature) -> bool:
        """Returns whether a Feature is active at a certain block."""
        state = self.get_state(block=block, feature=feature)

        return state == FeatureState.ACTIVE

    def get_state(self, *, block: Block, feature: Feature) -> FeatureState:
        """Returns the state of a feature at a certain block."""

        # per definition, the genesis block is in the DEFINED state for all features
        if block.is_genesis:
            return FeatureState.DEFINED

        # All blocks within the same evaluation interval have the same state, that is, the state is only defined for
        # the block in each interval boundary. Therefore, we get the state of the previous boundary.
        height = block.get_height()
        offset_to_boundary = height % self._settings.evaluation_interval
        offset_to_previous_boundary = offset_to_boundary or self._settings.evaluation_interval
        previous_boundary_height = height - offset_to_previous_boundary
        previous_boundary_block = _get_ancestor_at_height(block=block, height=previous_boundary_height)
        previous_state = self.get_state(block=previous_boundary_block, feature=feature)

        if offset_to_boundary != 0:
            return previous_state

        return self._calculate_new_state(
            boundary_block=block,
            feature=feature,
            previous_state=previous_state
        )

    def _calculate_new_state(
        self,
        *,
        boundary_block: Block,
        feature: Feature,
        previous_state: FeatureState
    ) -> FeatureState:
        """Returns the new feature state based on the new block, the criteria, and the previous state."""
        height = boundary_block.get_height()
        assert height % self._settings.evaluation_interval == 0, (
            'cannot calculate new state for a non-boundary block'
        )
        criteria = self._get_criteria(feature=feature)

        if previous_state is FeatureState.DEFINED:
            if height >= criteria.start_height:
                return FeatureState.STARTED

            return FeatureState.DEFINED

        if previous_state is FeatureState.STARTED:
            if height >= criteria.timeout_height and not criteria.activate_on_timeout:
                return FeatureState.FAILED

            if (
                height >= criteria.timeout_height
                and criteria.activate_on_timeout
                and height >= criteria.minimum_activation_height
            ):
                return FeatureState.ACTIVE

            count = self.get_bit_count(boundary_block=boundary_block, bit=criteria.bit)
            threshold = criteria.threshold if criteria.threshold is not None else self._settings.default_threshold

            if (
                height < criteria.timeout_height
                and count >= threshold
                and height >= criteria.minimum_activation_height
            ):
                return FeatureState.ACTIVE

            return FeatureState.STARTED

        if previous_state is FeatureState.ACTIVE:
            return FeatureState.ACTIVE

        if previous_state is FeatureState.FAILED:
            return FeatureState.FAILED

        raise ValueError(f'Unknown previous state: {previous_state}')

    def _get_criteria(self, *, feature: Feature) -> Criteria:
        """Get the Criteria defined for a specific Feature."""
        criteria = self._settings.features.get(feature)

        if not criteria:
            raise ValueError(f"Criteria not defined for feature '{feature}'.")

        return criteria

    def get_bits_description(self, *, block: Block) -> dict[Feature, FeatureDescription]:
        """Returns the criteria definition and feature state for all features at a certain block."""
        return {
            feature: FeatureDescription(
                criteria=criteria,
                state=self.get_state(block=block, feature=feature)
            )
            for feature, criteria in self._settings.features.items()
        }

    def get_bit_count(self, *, boundary_block: Block, bit: int) -> int:
        """Returns the count of blocks with this bit enabled in the previous evaluation interval."""
        assert not boundary_block.is_genesis, 'cannot calculate bit count for genesis'
        assert boundary_block.get_height() % self._settings.evaluation_interval == 0, (
            'cannot calculate bit count for a non-boundary block'
        )
        count = 0
        block = boundary_block

        # TODO: We can implement this as O(1) instead of O(evaluation_interval)
        #  by persisting the count in block metadata incrementally
        for _ in range(self._settings.evaluation_interval):
            block = block.get_block_parent()
            feature_bits = block.get_feature_activation_bits()
            bit_is_active = (feature_bits >> bit) & 1

            if bit_is_active:
                count += 1

        return count


def _get_ancestor_at_height(*, block: Block, height: int) -> Block:
    """Given a block, returns its ancestor at a specific height."""
    # TODO: there may be more optimized ways of doing this using the height index,
    #  but what if we're not in the best blockchain?
    assert height < block.get_height(), (
        f"ancestor height must be lower than the block's height: {height} >= {block.get_height()}"
    )

    ancestor = block
    while ancestor.get_height() > height:
        ancestor = ancestor.get_block_parent()

    return ancestor
