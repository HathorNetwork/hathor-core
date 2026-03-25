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

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

from hathor.conf.get_settings import get_global_settings

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings


def _get_settings(*, reduced_avg_time_10x: int = 75) -> HathorSettings:
    """Return settings with REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X configured."""
    return get_global_settings().model_copy(update={
        'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': reduced_avg_time_10x,
    })


class TestGetTokensIssuedPerBlock:
    """Tests for get_tokens_issued_per_block with REDUCE_DAA_TARGET feature."""

    def test_without_block_returns_normal_reward(self) -> None:
        settings = _get_settings()
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        reward = daa.get_tokens_issued_per_block(1)
        assert reward == settings.INITIAL_TOKENS_PER_BLOCK

    def test_with_block_feature_inactive(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = False
        daa = DifficultyAdjustmentAlgorithm(settings=settings, feature_service=feature_service)
        block = Mock()

        reward = daa.get_tokens_issued_per_block(1, block=block)
        assert reward == settings.INITIAL_TOKENS_PER_BLOCK

    def test_with_block_feature_active_reduces_reward(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        daa = DifficultyAdjustmentAlgorithm(settings=settings, feature_service=feature_service)
        block = Mock()

        reward = daa.get_tokens_issued_per_block(1, block=block)
        # AVG_TIME=30, REDUCED_10X=75 (7.5s), factor=300//75=4
        expected = settings.INITIAL_TOKENS_PER_BLOCK // 4
        assert reward == expected

    def test_no_feature_service_returns_normal_reward(self) -> None:
        settings = _get_settings()
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        block = Mock()

        reward = daa.get_tokens_issued_per_block(1, block=block)
        assert reward == settings.INITIAL_TOKENS_PER_BLOCK


class TestGetRewardForNextBlock:
    """Tests for get_reward_for_next_block."""

    def test_feature_inactive(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active_for_next_block.return_value = False
        daa = DifficultyAdjustmentAlgorithm(settings=settings, feature_service=feature_service)
        parent_block = Mock()
        parent_block.get_height.return_value = 10

        reward = daa.get_reward_for_next_block(parent_block)
        assert reward == settings.INITIAL_TOKENS_PER_BLOCK

    def test_feature_active_reduces_reward(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active_for_next_block.return_value = True
        daa = DifficultyAdjustmentAlgorithm(settings=settings, feature_service=feature_service)
        parent_block = Mock()
        parent_block.get_height.return_value = 10

        reward = daa.get_reward_for_next_block(parent_block)
        expected = settings.INITIAL_TOKENS_PER_BLOCK // 4
        assert reward == expected

    def test_no_feature_service(self) -> None:
        settings = _get_settings()
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        parent_block = Mock()
        parent_block.get_height.return_value = 10

        reward = daa.get_reward_for_next_block(parent_block)
        assert reward == settings.INITIAL_TOKENS_PER_BLOCK


class TestRewardReductionFactor:
    """Tests for _get_reward_reduction_factor."""

    def test_factor_30_to_7_5(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=75)
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        assert daa._get_reward_reduction_factor() == 4

    def test_factor_30_to_10(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=100)
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        assert daa._get_reward_reduction_factor() == 3

    def test_factor_30_to_15(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=150)
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        assert daa._get_reward_reduction_factor() == 2

    def test_factor_same_returns_1(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=300)
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        assert daa._get_reward_reduction_factor() == 1


class TestIsFeatureActiveForNextBlock:
    """Tests for FeatureService.is_feature_active_for_next_block."""

    def _make_service(
        self,
        *,
        evaluation_interval: int = 4,
        features: dict[Feature, Criteria] | None = None,
    ) -> FeatureService:
        if features is None:
            features = {}
        feature_settings = FeatureSettings.model_construct(
            evaluation_interval=evaluation_interval,
            default_threshold=3,
            features=features,
        )
        settings = get_global_settings().model_copy(update={'FEATURE_ACTIVATION': feature_settings})
        tx_storage = Mock()
        return FeatureService(settings=settings, tx_storage=tx_storage)

    def test_already_active(self) -> None:
        service = self._make_service()
        parent_block = Mock()

        with patch.object(FeatureService, 'get_state', return_value=FeatureState.ACTIVE):
            result = service.is_feature_active_for_next_block(
                parent_block=parent_block, feature=Feature.REDUCE_DAA_TARGET
            )
        assert result is True

    def test_defined_returns_false(self) -> None:
        service = self._make_service()
        parent_block = Mock()

        with patch.object(FeatureService, 'get_state', return_value=FeatureState.DEFINED):
            result = service.is_feature_active_for_next_block(
                parent_block=parent_block, feature=Feature.REDUCE_DAA_TARGET
            )
        assert result is False

    def test_started_returns_false(self) -> None:
        service = self._make_service()
        parent_block = Mock()

        with patch.object(FeatureService, 'get_state', return_value=FeatureState.STARTED):
            result = service.is_feature_active_for_next_block(
                parent_block=parent_block, feature=Feature.REDUCE_DAA_TARGET
            )
        assert result is False

    def test_locked_in_not_at_boundary(self) -> None:
        """LOCKED_IN but next block is NOT at an evaluation boundary -> False."""
        features = {
            Feature.REDUCE_DAA_TARGET: Criteria.model_construct(
                bit=0, start_height=0, timeout_height=400,
                minimum_activation_height=0, version=Mock()
            )
        }
        service = self._make_service(evaluation_interval=4, features=features)
        parent_block = Mock()
        parent_block.static_metadata = Mock()
        parent_block.static_metadata.height = 6  # next=7, 7 % 4 != 0

        with patch.object(FeatureService, 'get_state', return_value=FeatureState.LOCKED_IN):
            result = service.is_feature_active_for_next_block(
                parent_block=parent_block, feature=Feature.REDUCE_DAA_TARGET
            )
        assert result is False

    def test_locked_in_at_boundary_min_activation_met(self) -> None:
        """LOCKED_IN and next block IS at boundary and minimum_activation_height met -> True."""
        features = {
            Feature.REDUCE_DAA_TARGET: Criteria.model_construct(
                bit=0, start_height=0, timeout_height=400,
                minimum_activation_height=8, version=Mock()
            )
        }
        service = self._make_service(evaluation_interval=4, features=features)
        parent_block = Mock()
        parent_block.static_metadata = Mock()
        parent_block.static_metadata.height = 7  # next=8, 8 % 4 == 0 and 8 >= 8

        with patch.object(FeatureService, 'get_state', return_value=FeatureState.LOCKED_IN):
            result = service.is_feature_active_for_next_block(
                parent_block=parent_block, feature=Feature.REDUCE_DAA_TARGET
            )
        assert result is True

    def test_locked_in_at_boundary_min_activation_not_met(self) -> None:
        """LOCKED_IN and next block IS at boundary but minimum_activation_height NOT met -> False."""
        features = {
            Feature.REDUCE_DAA_TARGET: Criteria.model_construct(
                bit=0, start_height=0, timeout_height=400,
                minimum_activation_height=12, version=Mock()
            )
        }
        service = self._make_service(evaluation_interval=4, features=features)
        parent_block = Mock()
        parent_block.static_metadata = Mock()
        parent_block.static_metadata.height = 7  # next=8, 8 % 4 == 0 but 8 < 12

        with patch.object(FeatureService, 'get_state', return_value=FeatureState.LOCKED_IN):
            result = service.is_feature_active_for_next_block(
                parent_block=parent_block, feature=Feature.REDUCE_DAA_TARGET
            )
        assert result is False

    def test_locked_in_no_criteria(self) -> None:
        """LOCKED_IN at boundary but feature has no criteria -> False."""
        service = self._make_service(evaluation_interval=4, features={})
        parent_block = Mock()
        parent_block.static_metadata = Mock()
        parent_block.static_metadata.height = 7  # next=8, 8 % 4 == 0

        with patch.object(FeatureService, 'get_state', return_value=FeatureState.LOCKED_IN):
            result = service.is_feature_active_for_next_block(
                parent_block=parent_block, feature=Feature.REDUCE_DAA_TARGET
            )
        assert result is False


class TestEffectiveAvgTime:
    """Tests for _get_effective_avg_time."""

    def test_normal_avg_time(self) -> None:
        settings = _get_settings()
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        assert daa._get_effective_avg_time(reduce_active=False) == 30

    def test_reduced_avg_time(self) -> None:
        settings = _get_settings()
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        assert daa._get_effective_avg_time(reduce_active=True) == 7.5


class TestConsensusFeatureActivationRules:
    """Test that consensus handles REDUCE_DAA_TARGET feature."""

    def test_feature_activation_rules_handles_reduce_daa_target(self) -> None:
        """Ensure _feature_activation_rules does not raise for REDUCE_DAA_TARGET."""
        from hathor.consensus.consensus import ConsensusAlgorithm

        feature_service = Mock(spec=FeatureService)
        feature_service.get_feature_states.return_value = {
            Feature.REDUCE_DAA_TARGET: FeatureState.ACTIVE,
        }

        consensus = ConsensusAlgorithm.__new__(ConsensusAlgorithm)
        consensus.feature_service = feature_service

        tx = Mock()
        new_best_block = Mock()

        result = consensus._feature_activation_rules(tx, new_best_block)
        assert result is True
