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

from typing import TYPE_CHECKING, Any, Callable
from unittest.mock import Mock

from pytest import approx

from hathor.conf.get_settings import get_global_settings
from hathor.daa import DifficultyAdjustmentAlgorithm, DifficultyAdjustmentAlgorithmV1, DifficultyAdjustmentAlgorithmV2
from hathor.daa.common import TestMode, _calculate_next_weight
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.feature_state import FeatureState

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings


def _get_settings(*, reduced_avg_time_10x: int = 75) -> HathorSettings:
    """Return settings with REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X configured."""
    return get_global_settings().model_copy(update={
        'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': reduced_avg_time_10x,
    })


class TestDAAV1:
    """Tests for DifficultyAdjustmentAlgorithmV1."""

    def test_avg_time_between_blocks(self) -> None:
        settings = _get_settings()
        v1 = DifficultyAdjustmentAlgorithmV1(settings=settings)
        assert v1.avg_time_between_blocks == settings.AVG_TIME_BETWEEN_BLOCKS

    def test_get_tokens_issued_per_block_normal_reward(self) -> None:
        settings = _get_settings()
        v1 = DifficultyAdjustmentAlgorithmV1(settings=settings)
        assert v1.get_tokens_issued_per_block(1) == settings.INITIAL_TOKENS_PER_BLOCK


class TestDAAV2:
    """Tests for DifficultyAdjustmentAlgorithmV2."""

    def test_avg_time_between_blocks(self) -> None:
        settings = _get_settings()
        v2 = DifficultyAdjustmentAlgorithmV2(settings=settings)
        assert v2.avg_time_between_blocks == 7.5

    def test_get_tokens_issued_per_block_reduced_reward(self) -> None:
        settings = _get_settings()
        v2 = DifficultyAdjustmentAlgorithmV2(settings=settings)
        # AVG_TIME=30, REDUCED_10X=75 (7.5s), factor=300//75=4
        expected = settings.INITIAL_TOKENS_PER_BLOCK // 4
        assert v2.get_tokens_issued_per_block(1) == expected

    def test_reward_reduction_factor_30_to_7_5(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=75)
        v2 = DifficultyAdjustmentAlgorithmV2(settings=settings)
        assert v2._get_reward_reduction_factor() == 4

    def test_reward_reduction_factor_30_to_10(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=100)
        v2 = DifficultyAdjustmentAlgorithmV2(settings=settings)
        assert v2._get_reward_reduction_factor() == 3

    def test_reward_reduction_factor_30_to_15(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=150)
        v2 = DifficultyAdjustmentAlgorithmV2(settings=settings)
        assert v2._get_reward_reduction_factor() == 2

    def test_reward_reduction_factor_same_returns_1(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=300)
        v2 = DifficultyAdjustmentAlgorithmV2(settings=settings)
        assert v2._get_reward_reduction_factor() == 1


class TestFacadeGetTokensIssuedPerBlock:
    """Tests for the facade's get_tokens_issued_per_block with feature-based selection."""

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

    def test_no_feature_service_returns_v1_reward(self) -> None:
        settings = _get_settings()
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        block = Mock()

        reward = daa.get_tokens_issued_per_block(1, block=block)
        assert reward == settings.INITIAL_TOKENS_PER_BLOCK


class TestFacadeGetRewardForNextBlock:
    """Tests for the facade's get_reward_for_next_block."""

    def test_feature_inactive(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = False
        daa = DifficultyAdjustmentAlgorithm(settings=settings, feature_service=feature_service)
        parent_block = Mock()
        parent_block.get_height.return_value = 10

        reward = daa.get_reward_for_next_block(parent_block)
        assert reward == settings.INITIAL_TOKENS_PER_BLOCK

    def test_feature_active_reduces_reward(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
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


class TestFacadeSelect:
    """Tests for the facade's _select method."""

    def test_select_v1_without_feature_service(self) -> None:
        settings = _get_settings()
        daa = DifficultyAdjustmentAlgorithm(settings=settings)
        block = Mock()
        assert daa._select(block) == daa._v1

    def test_select_v1_when_feature_inactive(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = False
        daa = DifficultyAdjustmentAlgorithm(settings=settings, feature_service=feature_service)
        block = Mock()
        assert daa._select(block) == daa._v1

    def test_select_v2_when_feature_active(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        daa = DifficultyAdjustmentAlgorithm(settings=settings, feature_service=feature_service)
        block = Mock()
        assert daa._select(block) == daa._v2


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


# ---------------------------------------------------------------------------
# Helpers for DAA regression tests
# ---------------------------------------------------------------------------

class _MockBlock:
    """Lightweight mock block for DAA regression tests."""

    __slots__ = ('_height', 'timestamp', 'weight', 'hash')

    def __init__(self, height: int, timestamp: int, weight: float, hash_val: bytes = b'\x00' * 32) -> None:
        self._height = height
        self.timestamp = timestamp
        self.weight = weight
        self.hash = hash_val

    def get_height(self) -> int:
        return self._height


def _build_chain(
    n_blocks: int,
    interval: int,
    base_weight: float,
    base_timestamp: int = 1_000_000,
) -> tuple[list[_MockBlock], Callable[[_MockBlock], _MockBlock]]:
    """Build a linear chain of mock blocks and return (blocks, parent_getter)."""
    blocks: list[_MockBlock] = []
    for i in range(n_blocks + 1):
        blocks.append(_MockBlock(
            height=i,
            timestamp=base_timestamp + i * interval,
            weight=base_weight,
            hash_val=i.to_bytes(32, 'big'),
        ))
    parent_map: dict[int, _MockBlock] = {}
    for i in range(1, len(blocks)):
        parent_map[id(blocks[i])] = blocks[i - 1]

    def getter(b: _MockBlock) -> _MockBlock:
        return parent_map[id(b)]

    return blocks, getter


# ---------------------------------------------------------------------------
# Hardcoded regression tests for _calculate_next_weight
# ---------------------------------------------------------------------------

class TestDAAV1Regression:
    """Regression tests ensuring V1 (avg_time=30s) produces identical results to master."""

    def _run(self, blocks: list[_MockBlock], getter: Callable[..., Any], interval: int) -> float:
        settings = _get_settings()
        parent = blocks[-1]
        ts = parent.timestamp + interval
        return _calculate_next_weight(
            settings, parent, ts, getter,  # type: ignore[arg-type]
            avg_time=30.0, min_block_weight=21, test_mode=TestMode.DISABLED,
        )

    def test_steady_state_30s(self) -> None:
        """300 blocks at exactly 30s intervals, weight=25.0 -> weight stays ~25.0."""
        blocks, getter = _build_chain(300, 30, 25.0)
        w = self._run(blocks, getter, 30)
        assert w == approx(25.0, abs=1e-10)

    def test_fast_blocks_15s(self) -> None:
        """300 blocks at 15s intervals, weight=25.0 -> V1 increases weight to ~26.0."""
        blocks, getter = _build_chain(300, 15, 25.0)
        w = self._run(blocks, getter, 15)
        assert w == approx(26.0, abs=1e-10)

    def test_slow_blocks_60s(self) -> None:
        """300 blocks at 60s intervals, weight=25.0 -> V1 decreases weight to ~24.0."""
        blocks, getter = _build_chain(300, 60, 25.0)
        w = self._run(blocks, getter, 60)
        assert w == approx(24.0, abs=1e-10)


class TestDAAV2Regression:
    """Regression tests ensuring V2 (avg_time=7.5s) produces correct results."""

    def _run(self, blocks: list[_MockBlock], getter: Callable[..., Any], interval: int) -> float:
        settings = _get_settings()
        parent = blocks[-1]
        ts = parent.timestamp + interval
        return _calculate_next_weight(
            settings, parent, ts, getter,  # type: ignore[arg-type]
            avg_time=7.5, min_block_weight=21, test_mode=TestMode.DISABLED,
        )

    def test_steady_state_30s(self) -> None:
        """Blocks at 30s but V2 targets 7.5s -> weight drops to ~23.0 (blocks are slow for V2)."""
        blocks, getter = _build_chain(300, 30, 25.0)
        w = self._run(blocks, getter, 30)
        assert w == approx(23.0, abs=1e-10)

    def test_fast_blocks_15s(self) -> None:
        """Blocks at 15s, V2 targets 7.5s -> weight is ~24.0."""
        blocks, getter = _build_chain(300, 15, 25.0)
        w = self._run(blocks, getter, 15)
        assert w == approx(24.0, abs=1e-10)

    def test_slow_blocks_60s(self) -> None:
        """Blocks at 60s, V2 targets 7.5s -> weight drops to ~22.0."""
        blocks, getter = _build_chain(300, 60, 25.0)
        w = self._run(blocks, getter, 60)
        assert w == approx(22.0, abs=1e-10)
