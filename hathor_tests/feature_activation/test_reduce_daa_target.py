# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable
from unittest.mock import Mock

import pytest
from pytest import approx

from hathor.conf.get_settings import get_global_settings
from hathor.daa import DAAConfig, DAAFactory, DifficultyAdjustmentAlgorithm
from hathor.daa.common import _calculate_next_weight
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.feature_state import FeatureState
from hathor_tests.token_amount import UnsignedAmount

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings


def _get_settings(*, reduced_avg_time_10x: int = 75) -> HathorSettings:
    """Return settings with REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X configured."""
    return get_global_settings().model_copy(update={
        'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': reduced_avg_time_10x,
    })


def _make_v1(settings: HathorSettings) -> DifficultyAdjustmentAlgorithm:
    return DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v1(settings))


def _make_v2(settings: HathorSettings, *, v2_start_height: int | None = 1) -> DifficultyAdjustmentAlgorithm:
    """Build a V2 DAA. ``v2_start_height`` defaults to 1 (entire chain is V2) for tests
    that don't care about the V1->V2 boundary; pass it explicitly to exercise the split."""
    return DifficultyAdjustmentAlgorithm(
        settings=settings, config=DAAConfig.for_v2(settings, v2_start_height=v2_start_height),
    )


class TestDAAConfig:
    """Tests for the ``DAAConfig`` value object — the values that distinguish each version."""

    def test_v1_config_uses_settings_avg_time(self) -> None:
        settings = _get_settings()
        config = DAAConfig.for_v1(settings)
        assert config.avg_time_between_blocks == settings.AVG_TIME_BETWEEN_BLOCKS
        assert config.reward_reduction_factor == 1

    def test_v2_config_uses_reduced_avg_time(self) -> None:
        settings = _get_settings()
        config = DAAConfig.for_v2(settings)
        assert config.avg_time_between_blocks == 7.5
        # AVG_TIME=30, REDUCED_10X=75 (7.5s), factor=300//75=4
        assert config.reward_reduction_factor == 4

    def test_v2_reduction_factor_30_to_10(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=100)
        assert DAAConfig.for_v2(settings).reward_reduction_factor == 3

    def test_v2_reduction_factor_30_to_15(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=150)
        assert DAAConfig.for_v2(settings).reward_reduction_factor == 2

    def test_v2_reduction_factor_same_returns_1(self) -> None:
        settings = _get_settings(reduced_avg_time_10x=300)
        assert DAAConfig.for_v2(settings).reward_reduction_factor == 1


class TestAlgorithmV1:
    """Tests for ``DifficultyAdjustmentAlgorithm`` configured with the V1 config."""

    def test_avg_time_between_blocks(self) -> None:
        settings = _get_settings()
        v1 = _make_v1(settings)
        assert v1.avg_time_between_blocks == settings.AVG_TIME_BETWEEN_BLOCKS

    def test_get_tokens_issued_per_block_normal_reward(self) -> None:
        settings = _get_settings()
        v1 = _make_v1(settings)
        assert v1.get_tokens_issued_per_block(1) == UnsignedAmount.from_v1(
            settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK
        )

    def test_get_mined_tokens_matches_per_block_sum(self) -> None:
        settings = _get_settings()
        v1 = _make_v1(settings)
        # The cumulative count must equal summing per-block rewards 1..height.
        height = 5
        expected = sum(v1.get_tokens_issued_per_block(h) for h in range(1, height + 1))
        assert v1.get_mined_tokens(height) == expected


class TestAlgorithmV2:
    """Tests for ``DifficultyAdjustmentAlgorithm`` configured with the V2 config."""

    def test_avg_time_between_blocks(self) -> None:
        settings = _get_settings()
        v2 = _make_v2(settings)
        assert v2.avg_time_between_blocks == 7.5

    def test_get_tokens_issued_per_block_reduced_reward(self) -> None:
        settings = _get_settings()
        v2 = _make_v2(settings)
        # AVG_TIME=30, REDUCED_10X=75 (7.5s), factor=300//75=4
        expected = UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK // 4)
        assert v2.get_tokens_issued_per_block(1) == expected

    def test_get_mined_tokens_uses_reduced_reward(self) -> None:
        # _make_v2 defaults to v2_start_height=1 — entire chain is V2.
        settings = _get_settings()
        v2 = _make_v2(settings)
        height = 5
        # The cumulative count must equal summing V2's per-block rewards 1..height.
        expected = sum(v2.get_tokens_issued_per_block(h) for h in range(1, height + 1))
        assert v2.get_mined_tokens(height) == expected
        # And it must be strictly less than V1's count (factor=4, all blocks mid-halving).
        v1 = _make_v1(settings)
        assert v2.get_mined_tokens(height) == v1.get_mined_tokens(height) // 4


class TestGetMinedTokensV2StartHeight:
    """Tests for V1/V2-split cumulative reward accounting.

    The whole point: ``reward_reduction_factor`` only applies to heights at or above
    ``v2_start_height``. Blocks mined before activation keep the full V1 reward, so
    cumulative mined tokens cannot just divide the entire chain by the factor.
    """

    def test_v2_without_v2_start_height_asserts(self) -> None:
        settings = _get_settings()
        v2 = DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v2(settings))
        # V2 with no v2_start_height cannot meaningfully compute cumulative mined tokens —
        # we'd otherwise reproduce the bug where every block gets divided by the factor.
        try:
            v2.get_mined_tokens(10)
        except AssertionError:
            return
        raise AssertionError('expected AssertionError when v2_start_height is missing')

    def test_v2_start_height_at_1_is_all_v2(self) -> None:
        settings = _get_settings()
        v2 = _make_v2(settings, v2_start_height=1)
        v1 = _make_v1(settings)
        height = 5
        # All five blocks reduced by factor 4.
        assert v2.get_mined_tokens(height) == v1.get_mined_tokens(height) // 4

    def test_v2_start_height_beyond_height_is_all_v1(self) -> None:
        settings = _get_settings()
        v2 = _make_v2(settings, v2_start_height=1000)
        v1 = _make_v1(settings)
        height = 5
        # Activation hasn't happened yet within [1..height], so no reduction.
        assert v2.get_mined_tokens(height) == v1.get_mined_tokens(height)

    def test_v2_start_height_in_middle_splits_v1_v2(self) -> None:
        settings = _get_settings()
        v2_start_height = 3
        height = 5
        v2 = _make_v2(settings, v2_start_height=v2_start_height)
        v1 = _make_v1(settings)
        # Heights [1, 2] V1; [3, 5] V2. Sum each per-block reward to verify.
        v1_part = sum(v1.get_tokens_issued_per_block(h) for h in range(1, v2_start_height))
        v2_part = sum(v2.get_tokens_issued_per_block(h) for h in range(v2_start_height, height + 1))
        assert v2.get_mined_tokens(height) == v1_part + v2_part

    def test_v2_start_height_one_past_height_only_one_v2_block(self) -> None:
        settings = _get_settings()
        v2 = _make_v2(settings, v2_start_height=5)
        v1 = _make_v1(settings)
        # Heights [1..4] V1, height 5 V2.
        expected = (
            v1.get_mined_tokens(4)
            + v2.get_tokens_issued_per_block(5)
        )
        assert v2.get_mined_tokens(5) == expected

    def test_split_against_per_block_sum(self) -> None:
        # Cross-check the closed-form math against a per-block summation across the boundary.
        settings = _get_settings()
        v2_start_height = 7
        height = 12
        v2 = _make_v2(settings, v2_start_height=v2_start_height)
        v1 = _make_v1(settings)
        manual = sum(
            v1.get_tokens_issued_per_block(h) if h < v2_start_height
            else v2.get_tokens_issued_per_block(h)
            for h in range(1, height + 1)
        )
        assert v2.get_mined_tokens(height) == manual

    def test_split_across_halving_boundary(self) -> None:
        # When v2_start_height crosses a halving boundary, both halving math and the
        # V1/V2 split must compose correctly.
        settings = _get_settings()
        bph = settings.BLOCKS_PER_HALVING
        assert bph is not None
        v2_start_height = bph - 2  # straddle the next-halving boundary
        height = bph + 3
        v2 = _make_v2(settings, v2_start_height=v2_start_height)
        v1 = _make_v1(settings)
        manual = sum(
            v1.get_tokens_issued_per_block(h) if h < v2_start_height
            else v2.get_tokens_issued_per_block(h)
            for h in range(1, height + 1)
        )
        assert v2.get_mined_tokens(height) == manual

    def test_v1_ignores_v2_start_height(self) -> None:
        # V1 configs never carry v2_start_height (factory doesn't set it), and even if
        # someone constructed one with it, factor=1 short-circuits the reduction.
        settings = _get_settings()
        v1_with_garbage = DifficultyAdjustmentAlgorithm(
            settings=settings,
            config=DAAConfig(
                avg_time_between_blocks=settings.AVG_TIME_BETWEEN_BLOCKS,
                reward_reduction_factor=1,
                v2_start_height=3,
            ),
        )
        v1 = _make_v1(settings)
        assert v1_with_garbage.get_mined_tokens(10) == v1.get_mined_tokens(10)


class TestDAAFactorySelect:
    """Tests for ``DAAFactory._select_config`` — version selection by parent feature state.

    Shape B: a block is V2 iff its parent is in REDUCE_DAA_TARGET ACTIVE state.
    """

    def test_select_asserts_without_feature_service(self) -> None:
        # Production paths must wire feature_service; CLI/tests use create_v1 directly.
        settings = _get_settings()
        factory = DAAFactory(settings=settings)
        parent_block = Mock()
        with pytest.raises(AssertionError, match='feature_service'):
            factory._select_config(parent_block)

    def test_select_v1_when_parent_feature_inactive(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = False
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()
        assert factory._select_config(parent_block) == DAAConfig.for_v1(settings)

    def test_select_v2_when_parent_feature_active(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        feature_service.get_activation_height.return_value = 16
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()
        # Shape B: v2_start_height = activation_height + 1.
        assert factory._select_config(parent_block) == DAAConfig.for_v2(settings, v2_start_height=17)


class TestDAAFactoryCreateFromBlock:
    """Tests for ``DAAFactory.create_from_block`` — feature-aware DAA construction."""

    def _mock_non_genesis_block(self) -> Mock:
        block = Mock()
        block.is_genesis = False
        block.get_block_parent.return_value = Mock()
        return block

    def test_with_block_parent_feature_inactive(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = False
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        block = self._mock_non_genesis_block()

        reward = factory.create_from_block(block).get_tokens_issued_per_block(1)
        assert reward == UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK)

    def test_with_block_parent_feature_active_reduces_reward(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        feature_service.get_activation_height.return_value = 0
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        block = self._mock_non_genesis_block()

        reward = factory.create_from_block(block).get_tokens_issued_per_block(1)
        # AVG_TIME=30, REDUCED_10X=75 (7.5s), factor=300//75=4
        expected = UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK // 4)
        assert reward == expected

    def test_create_from_block_asserts_without_feature_service(self) -> None:
        settings = _get_settings()
        factory = DAAFactory(settings=settings)
        block = self._mock_non_genesis_block()

        with pytest.raises(AssertionError, match='feature_service'):
            factory.create_from_block(block)

    def test_with_genesis_block_returns_v1_reward(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        block = Mock()
        block.is_genesis = True

        reward = factory.create_from_block(block).get_tokens_issued_per_block(1)
        assert reward == UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK)


class TestDAAFactoryRewardForNextBlock:
    """Tests for ``create_from_parent(parent).get_reward_for_next_block(parent)``."""

    def test_feature_inactive(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = False
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()
        parent_block.get_height.return_value = 10

        reward = factory.create_from_parent(parent_block).get_reward_for_next_block(parent_block)
        assert reward == UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK)

    def test_feature_active_reduces_reward(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        feature_service.get_activation_height.return_value = 0
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()
        parent_block.get_height.return_value = 10

        reward = factory.create_from_parent(parent_block).get_reward_for_next_block(parent_block)
        expected = UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK // 4)
        assert reward == expected

    def test_create_from_parent_asserts_without_feature_service(self) -> None:
        settings = _get_settings()
        factory = DAAFactory(settings=settings)
        parent_block = Mock()
        parent_block.get_height.return_value = 10

        with pytest.raises(AssertionError, match='feature_service'):
            factory.create_from_parent(parent_block)


class TestDAAFactoryV2StartHeight:
    """Tests that ``DAAFactory.create_from_parent`` threads v2_start_height through.

    The factory is the only place that has feature_service, so it is the one responsible
    for computing where V2 took effect and handing it to the DAA.
    """

    def test_create_from_parent_v1_does_not_set_v2_start_height(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = False
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()

        daa = factory.create_from_parent(parent_block)
        assert daa._config.v2_start_height is None
        # And feature_service.get_activation_height must NOT have been queried — it's only
        # needed when V2 is selected.
        feature_service.get_activation_height.assert_not_called()

    def test_create_from_parent_v2_sets_v2_start_height(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        feature_service.get_activation_height.return_value = 16
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()

        daa = factory.create_from_parent(parent_block)
        # Shape B: first V2 block is the one AFTER the activation block, so v2_start_height
        # is activation_height + 1.
        assert daa._config.v2_start_height == 17

    def test_create_from_parent_v2_passes_correct_feature(self) -> None:
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        feature_service.get_activation_height.return_value = 16
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()

        factory.create_from_parent(parent_block)
        feature_service.get_activation_height.assert_called_once_with(
            block=parent_block, feature=Feature.REDUCE_DAA_TARGET,
        )

    def test_create_from_parent_v2_get_mined_tokens_is_split(self) -> None:
        # End-to-end through the factory: reproduce the V1/V2 split via the factory wiring.
        settings = _get_settings()
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.return_value = True
        feature_service.get_activation_height.return_value = 4  # → v2_start_height=5
        factory = DAAFactory(settings=settings, feature_service=feature_service)
        parent_block = Mock()

        daa = factory.create_from_parent(parent_block)
        v1 = _make_v1(settings)
        # Heights [1..4] V1, [5..10] V2.
        manual = sum(v1.get_tokens_issued_per_block(h) for h in range(1, 5)) + \
            sum(daa.get_tokens_issued_per_block(h) for h in range(5, 11))
        assert daa.get_mined_tokens(10) == manual


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
            avg_time=30.0, min_block_weight=21,
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
            avg_time=7.5, min_block_weight=21,
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


# ---------------------------------------------------------------------------
# Boundary test: mine and verify across the LOCKED_IN -> ACTIVE transition via
# the real manager + BlockVerifier path. Shape B semantics: the activation
# block itself is still V1 (its parent is LOCKED_IN); V2 begins at the block
# AFTER the activation block (parent is ACTIVE).
# ---------------------------------------------------------------------------

from hathor.builder import Builder  # noqa: E402
from hathor.feature_activation.model.criteria import Criteria  # noqa: E402
from hathor.feature_activation.settings import Settings as FeatureSettings  # noqa: E402
from hathor.simulator.utils import add_new_blocks  # noqa: E402
from hathor_tests.simulation.base import SimulatorTestCase  # noqa: E402


class ActivationBoundaryTest(SimulatorTestCase):
    """Exercise the template/verification round-trip across the REDUCE_DAA_TARGET boundary."""

    def get_simulator_builder(self) -> Builder:
        return self.simulator.get_default_builder()

    def test_mines_through_activation_boundary(self) -> None:
        """Blocks immediately before, at, and after the activation height must all verify."""
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            max_signal_bits=4,
            default_threshold=3,
            features={
                Feature.REDUCE_DAA_TARGET: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    minimum_activation_height=16,
                    lock_in_on_timeout=True,
                    version='0.0.0',
                )
            }
        )
        settings = get_global_settings().model_copy(update={
            'FEATURE_ACTIVATION': feature_settings,
            'REWARD_SPEND_MIN_BLOCKS': 0,
            'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': 75,
        })
        self.simulator.settings = settings
        builder = self.get_simulator_builder().set_settings(settings)
        artifacts = self.simulator.create_artifacts(builder)
        manager = artifacts.manager
        feature_service = artifacts.feature_service

        # Simulator.create_artifacts builds the DAA factory without feature_service (line ~112
        # of hathor/simulator/simulator.py), so we have to inject it ourselves — same
        # workaround the tools/daa-reduction/simulator/ scripts use. Without this, the
        # factory's _feature_service is None and selection always returns V1, making the
        # feature a no-op and making this test pointless.
        manager.daa_factory._feature_service = feature_service

        # Mine up to height 15 (last LOCKED_IN-era block) with signaling on bit 0.
        # Activation height is 16.
        blocks = add_new_blocks(manager, 15, signal_bits=0b1)
        assert blocks[-1].get_height() == 15
        assert feature_service.get_state(
            block=blocks[-1], feature=Feature.REDUCE_DAA_TARGET
        ) == FeatureState.LOCKED_IN

        # Mine the activation block (height 16). Under Shape B this is still V1
        # because its parent (height 15) is LOCKED_IN.
        [activation_block] = add_new_blocks(manager, 1, signal_bits=0b1)
        assert activation_block.get_height() == 16
        assert feature_service.get_state(
            block=activation_block, feature=Feature.REDUCE_DAA_TARGET
        ) == FeatureState.ACTIVE
        v1_reward = UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK)
        v2_reward = UnsignedAmount.from_v1(settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK // 4)
        assert activation_block.sum_outputs == v1_reward, (
            f'activation block (height 16) should still be V1 under Shape B '
            f'(parent at 15 is LOCKED_IN). got {activation_block.sum_outputs}, '
            f'expected V1={v1_reward}'
        )

        # Mine the first post-activation block (height 17). Its parent (block 16)
        # is ACTIVE, so it must use V2 reward.
        [first_v2_block] = add_new_blocks(manager, 1, signal_bits=0b1)
        assert first_v2_block.get_height() == 17
        assert first_v2_block.sum_outputs == v2_reward, (
            f'first post-activation block (height 17) should use V2 (parent at 16 '
            f'is ACTIVE). got {first_v2_block.sum_outputs}, expected V2={v2_reward}'
        )

        # Steady-state V2 for subsequent blocks.
        post = add_new_blocks(manager, 3, signal_bits=0b1)
        for b in post:
            assert b.sum_outputs == v2_reward

        # End-to-end: cumulative mined tokens must match summing actual block rewards
        # one-by-one. This is the regression we care about — applying the reduction
        # factor to the entire chain (instead of only post-activation heights) breaks here.
        last_block = post[-1]
        last_height = last_block.get_height()
        assert last_height == 20

        daa = manager.daa_factory.create_from_parent(last_block)
        # Activation boundary is 16; first V2 block is 17. v2_start_height = 17.
        assert daa._config.v2_start_height == 17

        per_block_sum = 16 * v1_reward.raw() + (last_height - 16) * v2_reward.raw()
        assert daa.get_mined_tokens(last_height) == per_block_sum, (
            f'cumulative mined tokens at height {last_height} should split V1[1..16]+V2[17..20]: '
            f'got {daa.get_mined_tokens(last_height)}, expected {per_block_sum}'
        )

        # Sanity: had we (incorrectly) applied the reduction factor to the entire chain,
        # we would get this wrong number — verify we are NOT producing it.
        wrong_all_v2 = last_height * v2_reward.raw()
        assert daa.get_mined_tokens(last_height) != wrong_all_v2

    def test_get_activation_height_walks_back_through_boundaries(self) -> None:
        """FeatureService.get_activation_height returns the first ACTIVE boundary, even
        when several boundaries have already passed since activation."""
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            max_signal_bits=4,
            default_threshold=3,
            features={
                Feature.REDUCE_DAA_TARGET: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    minimum_activation_height=16,
                    lock_in_on_timeout=True,
                    version='0.0.0',
                )
            }
        )
        settings = get_global_settings().model_copy(update={
            'FEATURE_ACTIVATION': feature_settings,
            'REWARD_SPEND_MIN_BLOCKS': 0,
            'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': 75,
        })
        self.simulator.settings = settings
        builder = self.get_simulator_builder().set_settings(settings)
        artifacts = self.simulator.create_artifacts(builder)
        manager = artifacts.manager
        feature_service = artifacts.feature_service
        manager.daa_factory._feature_service = feature_service

        # Mine to height 15 first to be safe — activation height is 16.
        add_new_blocks(manager, 15, signal_bits=0b1)
        # Mine well past activation so multiple boundaries have ACTIVE state.
        # Activation at 16; we cross boundaries at 20, 24, 28...
        post = add_new_blocks(manager, 17, signal_bits=0b1)
        last_block = post[-1]
        assert last_block.get_height() == 32

        # All boundaries from 16 onwards are ACTIVE; the helper must walk back and report 16.
        activation_height = feature_service.get_activation_height(
            block=last_block, feature=Feature.REDUCE_DAA_TARGET,
        )
        assert activation_height == 16, (
            f'expected activation_height to be the first ACTIVE boundary (16), got {activation_height}'
        )

        # And before activation, the helper returns None.
        pre_activation_block = manager.tx_storage.get_block_by_height(15)
        assert pre_activation_block is not None
        assert feature_service.get_activation_height(
            block=pre_activation_block, feature=Feature.REDUCE_DAA_TARGET,
        ) is None
