# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RESTORE_DAA_TARGET feature (DAA V3).

DAA V3 restores the original block target (30s) and the full block reward after REDUCE_DAA_TARGET (DAA V2)
had reduced both. REDUCE_DAA_TARGET stays ACTIVE forever (it also gates the Nano runtime V2), so V3 must take
precedence over it, and the V1 -> V2 -> V3 history must remain consistent: blocks of each era are verified with
the rules of their own era, and cumulative rewards account for each range separately.
"""

from __future__ import annotations

from math import log2
from typing import TYPE_CHECKING, Any, Callable
from unittest.mock import Mock

import pytest
from pytest import approx
from twisted.python.failure import Failure

from hathor.builder import Builder
from hathor.conf.get_settings import get_global_settings
from hathor.daa import DAAConfig, DAAFactory, DAAVersion, DifficultyAdjustmentAlgorithm
from hathor.daa.common import _calculate_next_weight
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.feature_activation.utils import Features
from hathor.simulator import FakeConnection
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Block
from hathor.transaction.exceptions import InvalidBlockReward
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor_tests.simulation.base import SimulatorTestCase
from hathorlib.conf.settings import FeatureSetting

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.manager import HathorManager


def _get_settings() -> HathorSettings:
    return get_global_settings().model_copy(update={
        'AVG_TIME_BETWEEN_BLOCKS': 30,
        'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': 75,
    })


def _active_features(*features: Feature) -> Callable[..., bool]:
    """Return a `FeatureService.is_feature_active` side effect where only `features` are active."""
    def is_feature_active(*, vertex: Any, feature: Feature) -> bool:
        return feature in features
    return is_feature_active


def _activation_heights(heights: dict[Feature, int]) -> Callable[..., int | None]:
    """Return a `FeatureService.get_activation_height` side effect with the given activation heights."""
    def get_activation_height(*, block: Any, feature: Feature) -> int | None:
        return heights.get(feature)
    return get_activation_height


def _per_block_rewards(settings: HathorSettings, height: int, *, v2_start: int, v3_start: int) -> int:
    """Sum per-block rewards 1..height, the slow way, as the reference for `get_mined_tokens`."""
    v1 = DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v1(settings))
    v2 = DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v2(settings))
    return sum(
        int((v2 if v2_start <= h < v3_start else v1).get_tokens_issued_per_block(h))
        for h in range(1, height + 1)
    )


class TestDAAConfigV3:
    def test_v3_config_restores_v1_target_and_reward(self) -> None:
        settings = _get_settings()
        config = DAAConfig.for_v3(settings, v2_start_height=17, v3_start_height=33)
        assert config.avg_time_between_blocks == settings.AVG_TIME_BETWEEN_BLOCKS == 30
        assert config.reward_reduction_factor == 1
        assert config.v2_start_height == 17
        assert config.v3_start_height == 33

    def test_v3_per_block_reward_equals_v1(self) -> None:
        settings = _get_settings()
        v1 = DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v1(settings))
        v3 = DifficultyAdjustmentAlgorithm(
            settings=settings, config=DAAConfig.for_v3(settings, v2_start_height=17, v3_start_height=33),
        )
        assert v3.avg_time_between_blocks == v1.avg_time_between_blocks
        for height in (1, 33, 100, 1000):
            assert v3.get_tokens_issued_per_block(height) == v1.get_tokens_issued_per_block(height)


class TestGetMinedTokensV3:
    """Cumulative rewards must split V1 / V2 / V3 ranges; only V2 is reduced."""

    def _v3(self, settings: HathorSettings, *, v2_start: int | None, v3_start: int) -> DifficultyAdjustmentAlgorithm:
        return DifficultyAdjustmentAlgorithm(
            settings=settings, config=DAAConfig.for_v3(settings, v2_start_height=v2_start, v3_start_height=v3_start),
        )

    def test_three_ranges_match_per_block_sum(self) -> None:
        settings = _get_settings()
        daa = self._v3(settings, v2_start=7, v3_start=13)
        for height in range(1, 30):
            expected = _per_block_rewards(settings, height, v2_start=7, v3_start=13)
            assert daa.get_mined_tokens(height) == expected, height

    def test_three_ranges_across_halvings(self) -> None:
        settings = _get_settings()
        bph = settings.BLOCKS_PER_HALVING
        assert bph is not None
        # V2 straddles one halving boundary, V3 straddles the next one.
        v2_start, v3_start = bph - 2, 2 * bph - 3
        height = 2 * bph + 5
        daa = self._v3(settings, v2_start=v2_start, v3_start=v3_start)
        assert daa.get_mined_tokens(height) == _per_block_rewards(
            settings, height, v2_start=v2_start, v3_start=v3_start,
        )

    def test_v3_start_beyond_height_is_same_as_v2(self) -> None:
        settings = _get_settings()
        v2 = DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v2(settings, v2_start_height=7))
        v3 = self._v3(settings, v2_start=7, v3_start=1000)
        assert v3.get_mined_tokens(20) == v2.get_mined_tokens(20)

    def test_without_v2_history_is_all_v1(self) -> None:
        # RESTORE_DAA_TARGET activated on a chain where REDUCE_DAA_TARGET never did.
        settings = _get_settings()
        v1 = DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v1(settings))
        v3 = self._v3(settings, v2_start=None, v3_start=5)
        assert v3.get_mined_tokens(20) == v1.get_mined_tokens(20)

    def test_v3_takes_precedence_over_later_v2(self) -> None:
        # Misconfiguration guard: if V2 would start after V3, V3 wins and there is no V2 range.
        settings = _get_settings()
        v1 = DifficultyAdjustmentAlgorithm(settings=settings, config=DAAConfig.for_v1(settings))
        v3 = self._v3(settings, v2_start=10, v3_start=5)
        assert v3.get_mined_tokens(20) == v1.get_mined_tokens(20)


class TestDAAFactorySelectV3:
    """`DAAFactory._select_config` with RESTORE_DAA_TARGET. Shape B: start height = activation height + 1."""

    def _factory(
        self,
        settings: HathorSettings,
        *,
        active: tuple[Feature, ...],
        heights: dict[Feature, int],
    ) -> tuple[DAAFactory, Mock]:
        feature_service = Mock(spec=FeatureService)
        feature_service.is_feature_active.side_effect = _active_features(*active)
        feature_service.get_activation_height.side_effect = _activation_heights(heights)
        return DAAFactory(settings=settings, feature_service=feature_service), feature_service

    def test_both_active_selects_v3(self) -> None:
        settings = _get_settings()
        factory, _ = self._factory(
            settings,
            active=(Feature.REDUCE_DAA_TARGET, Feature.RESTORE_DAA_TARGET),
            heights={Feature.REDUCE_DAA_TARGET: 16, Feature.RESTORE_DAA_TARGET: 32},
        )
        assert factory._select_config(Mock()) == DAAConfig.for_v3(settings, v2_start_height=17, v3_start_height=33)

    def test_only_reduce_active_selects_v2(self) -> None:
        settings = _get_settings()
        factory, feature_service = self._factory(
            settings,
            active=(Feature.REDUCE_DAA_TARGET,),
            heights={Feature.REDUCE_DAA_TARGET: 16},
        )
        assert factory._select_config(Mock()) == DAAConfig.for_v2(settings, v2_start_height=17)

    def test_only_restore_active_selects_v3_without_v2_range(self) -> None:
        settings = _get_settings()
        factory, _ = self._factory(
            settings,
            active=(Feature.RESTORE_DAA_TARGET,),
            heights={Feature.RESTORE_DAA_TARGET: 32},
        )
        assert factory._select_config(Mock()) == DAAConfig.for_v3(settings, v2_start_height=None, v3_start_height=33)

    def test_none_active_selects_v1(self) -> None:
        settings = _get_settings()
        factory, feature_service = self._factory(settings, active=(), heights={})
        assert factory._select_config(Mock()) == DAAConfig.for_v1(settings)
        feature_service.get_activation_height.assert_not_called()

    def test_v3_reward_is_full_and_mined_tokens_split(self) -> None:
        settings = _get_settings()
        factory, _ = self._factory(
            settings,
            active=(Feature.REDUCE_DAA_TARGET, Feature.RESTORE_DAA_TARGET),
            heights={Feature.REDUCE_DAA_TARGET: 4, Feature.RESTORE_DAA_TARGET: 8},
        )
        parent_block = Mock()
        parent_block.get_height.return_value = 20
        daa = factory.create_from_parent(parent_block)
        assert daa.get_reward_for_next_block(parent_block) == settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK
        # Heights [1..4] V1, [5..8] V2, [9..20] V3.
        assert daa.get_mined_tokens(20) == _per_block_rewards(settings, 20, v2_start=5, v3_start=9)


class TestFeaturesDAAVersion:
    def _features(self, states: dict[Feature, FeatureState]) -> Features:
        settings = _get_settings().model_copy(update={
            'ENABLE_DAA_V2': FeatureSetting.FEATURE_ACTIVATION,
            'ENABLE_DAA_V3': FeatureSetting.FEATURE_ACTIVATION,
        })
        feature_service = Mock(spec=FeatureService)
        feature_service.get_feature_states.return_value = states
        return Features.from_vertex(settings=settings, feature_service=feature_service, vertex=Mock())

    def test_daa_version(self) -> None:
        assert self._features({}).daa_version == DAAVersion.V1
        assert self._features({Feature.REDUCE_DAA_TARGET: FeatureState.ACTIVE}).daa_version == DAAVersion.V2
        assert self._features({
            Feature.REDUCE_DAA_TARGET: FeatureState.ACTIVE,
            Feature.RESTORE_DAA_TARGET: FeatureState.LOCKED_IN,
        }).daa_version == DAAVersion.V2
        assert self._features({
            Feature.REDUCE_DAA_TARGET: FeatureState.ACTIVE,
            Feature.RESTORE_DAA_TARGET: FeatureState.ACTIVE,
        }).daa_version == DAAVersion.V3

    def test_restore_keeps_nano_runtime_v2(self) -> None:
        from hathor.nanocontracts.nano_runtime_version import NanoRuntimeVersion
        features = self._features({
            Feature.REDUCE_DAA_TARGET: FeatureState.ACTIVE,
            Feature.RESTORE_DAA_TARGET: FeatureState.ACTIVE,
        })
        assert features.nano_runtime_version == NanoRuntimeVersion.V2


class TestConsensusFeatureActivationRulesV3:
    def test_feature_activation_rules_handles_restore_daa_target(self) -> None:
        from hathor.consensus.consensus import ConsensusAlgorithm

        feature_service = Mock(spec=FeatureService)
        feature_service.get_feature_states.return_value = {
            Feature.REDUCE_DAA_TARGET: FeatureState.ACTIVE,
            Feature.RESTORE_DAA_TARGET: FeatureState.ACTIVE,
        }
        consensus = ConsensusAlgorithm.__new__(ConsensusAlgorithm)
        consensus.feature_service = feature_service
        assert consensus._feature_activation_rules(Mock(), Mock()) is True


# ---------------------------------------------------------------------------
# Block-time dynamics: drive the real `_calculate_next_weight` with a constant hashrate, where every block takes
# exactly its expected solvetime (2^weight / hashrate). This removes randomness and checks the DAA itself brings
# the block time from 30s to 7.5s (V2) and back to 30s (V3).
# ---------------------------------------------------------------------------

class _ModelBlock:
    __slots__ = ('timestamp', 'weight', 'parent')

    def __init__(self, timestamp: int, weight: float, parent: _ModelBlock | None) -> None:
        self.timestamp = timestamp
        self.weight = weight
        self.parent = parent

    def get_height(self) -> int:
        height, block = 0, self.parent
        while block is not None:
            height, block = height + 1, block.parent
        return height


def _get_parent(block: _ModelBlock) -> _ModelBlock:
    assert block.parent is not None
    return block.parent


class TestBlockTimeDynamics:
    HASHRATE = 2 ** 20  # hashes per second
    V1_BLOCKS = 300
    V2_BLOCKS = 600
    V3_BLOCKS = 600

    def _simulate(self) -> tuple[list[_ModelBlock], list[float]]:
        settings = _get_settings().model_copy(update={'WEIGHT_DECAY_ENABLED': False})
        w30 = log2(self.HASHRATE * 30)

        # Pre-history in V1 steady state, long enough to fill the DAA window.
        tip = _ModelBlock(0, w30, None)
        blocks = [tip]
        n_window = 2 * settings.BLOCK_DIFFICULTY_N_BLOCKS + 2
        for _ in range(n_window):
            tip = _ModelBlock(tip.timestamp + 30, w30, tip)
            blocks.append(tip)

        targets: list[float] = []
        schedule = [30.0] * self.V1_BLOCKS + [7.5] * self.V2_BLOCKS + [30.0] * self.V3_BLOCKS
        for avg_time in schedule:
            weight = _calculate_next_weight(
                settings, tip, tip.timestamp, _get_parent,  # type: ignore[arg-type]
                avg_time=avg_time, min_block_weight=settings.MIN_BLOCK_WEIGHT,
            )
            solvetime = max(1, round(2 ** weight / self.HASHRATE))
            tip = _ModelBlock(tip.timestamp + solvetime, weight, tip)
            blocks.append(tip)
            targets.append(avg_time)
        return blocks[n_window + 1:], targets

    @staticmethod
    def _avg_solvetime(blocks: list[_ModelBlock]) -> float:
        return (blocks[-1].timestamp - _get_parent(blocks[0]).timestamp) / len(blocks)

    def test_block_time_goes_30_to_7_5_and_back_to_30(self) -> None:
        blocks, _ = self._simulate()
        v1 = blocks[:self.V1_BLOCKS]
        v2 = blocks[self.V1_BLOCKS:self.V1_BLOCKS + self.V2_BLOCKS]
        v3 = blocks[self.V1_BLOCKS + self.V2_BLOCKS:]

        # Measure the second half of each era, after the DAA has converged.
        assert self._avg_solvetime(v1[-150:]) == approx(30.0, rel=0.05)
        assert self._avg_solvetime(v2[-300:]) == approx(7.5, rel=0.1)
        assert self._avg_solvetime(v3[-300:]) == approx(30.0, rel=0.05)

        w30 = log2(self.HASHRATE * 30)
        assert v3[-1].weight == approx(w30, abs=0.15)
        assert v2[-1].weight == approx(w30 - 2, abs=0.15)

    def test_first_v3_block_weight_jumps_by_log2_of_ratio(self) -> None:
        blocks, _ = self._simulate()
        last_v2 = blocks[self.V1_BLOCKS + self.V2_BLOCKS - 1]
        first_v3 = blocks[self.V1_BLOCKS + self.V2_BLOCKS]
        # log2(30 / 7.5) = 2: the DAA immediately targets 4x longer blocks.
        assert first_v3.weight - last_v2.weight == approx(2.0, abs=0.15)


# ---------------------------------------------------------------------------
# Full-node tests through the real manager, BlockVerifier, sync and reorg paths.
#
# Timeline (evaluation_interval=4):
# - REDUCE_DAA_TARGET: ACTIVE at 16 -> V2 from height 17.
# - RESTORE_DAA_TARGET: STARTED at 20, LOCKED_IN at 24, ACTIVE at 32 -> V3 from height 33.
# ---------------------------------------------------------------------------

REDUCE_ACTIVATION_HEIGHT = 16
RESTORE_ACTIVATION_HEIGHT = 32


class RestoreDAATargetSimulationTest(SimulatorTestCase):
    def setUp(self) -> None:
        super().setUp()
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            max_signal_bits=4,
            default_threshold=3,
            features={
                Feature.REDUCE_DAA_TARGET: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    minimum_activation_height=REDUCE_ACTIVATION_HEIGHT,
                    lock_in_on_timeout=True,
                    version='0.0.0',
                ),
                Feature.RESTORE_DAA_TARGET: Criteria(
                    bit=1,
                    start_height=20,
                    timeout_height=28,
                    minimum_activation_height=RESTORE_ACTIVATION_HEIGHT,
                    lock_in_on_timeout=True,
                    version='0.0.0',
                ),
            },
        )
        self.settings = get_global_settings().model_copy(update={
            'FEATURE_ACTIVATION': feature_settings,
            'ENABLE_DAA_V2': FeatureSetting.FEATURE_ACTIVATION,
            'ENABLE_DAA_V3': FeatureSetting.FEATURE_ACTIVATION,
            'REWARD_SPEND_MIN_BLOCKS': 0,
            'AVG_TIME_BETWEEN_BLOCKS': 30,
            'REDUCED_AVG_TIME_BETWEEN_BLOCKS_10X': 75,
        })
        self.simulator.settings = self.settings
        self.v1_reward = self.settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK
        self.v2_reward = self.settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK // 4

    def get_simulator_builder(self) -> Builder:
        return self.simulator.get_default_builder().set_settings(self.settings)

    def _create_manager(self) -> tuple[HathorManager, FeatureService]:
        artifacts = self.simulator.create_artifacts(self.get_simulator_builder())
        # The builder must wire the feature service into the DAA factory, otherwise V2/V3 are never selected.
        assert artifacts.manager.daa_factory._feature_service == artifacts.feature_service
        return artifacts.manager, artifacts.feature_service

    def _expected_reward(self, height: int) -> int:
        if REDUCE_ACTIVATION_HEIGHT < height <= RESTORE_ACTIVATION_HEIGHT:
            return self.v2_reward
        return self.v1_reward

    def _best_chain(self, manager: HathorManager) -> list[Block]:
        tip = manager.tx_storage.get_best_block()
        chain = []
        while not tip.is_genesis:
            chain.append(tip)
            tip = tip.get_block_parent()
        return list(reversed(chain))

    def _assert_consistent_history(self, manager: HathorManager) -> None:
        """Every best-chain block has the reward and target of its own era, and totals add up."""
        chain = self._best_chain(manager)
        for block in chain:
            height = block.get_height()
            assert block.get_metadata().validation.is_fully_connected(), height
            assert block.sum_outputs == self._expected_reward(height), height
            daa = manager.daa_factory.create_from_block(block)
            expected_avg_time = 7.5 if REDUCE_ACTIVATION_HEIGHT < height <= RESTORE_ACTIVATION_HEIGHT else 30
            assert daa.avg_time_between_blocks == expected_avg_time, height

        tip = chain[-1]
        daa = manager.daa_factory.create_from_parent(tip)
        assert daa._config.v2_start_height == REDUCE_ACTIVATION_HEIGHT + 1
        assert daa._config.v3_start_height == RESTORE_ACTIVATION_HEIGHT + 1
        # `get_mined_tokens` covers heights 1..tip (genesis outputs are the premine, not a reward). Each block's
        # reward was checked above, so the total is the sum of the rewards of each era.
        n_v2 = RESTORE_ACTIVATION_HEIGHT - REDUCE_ACTIVATION_HEIGHT
        n_v1 = tip.get_height() - n_v2
        assert daa.get_mined_tokens(tip.get_height()) == n_v1 * self.v1_reward + n_v2 * self.v2_reward

    def test_mines_through_reduce_and_restore(self) -> None:
        manager, feature_service = self._create_manager()
        blocks = add_new_blocks(manager, 40, signal_bits=0b11)
        by_height = {block.get_height(): block for block in blocks}

        def state(height: int, feature: Feature) -> FeatureState:
            return feature_service.get_state(block=by_height[height], feature=feature)

        assert state(15, Feature.REDUCE_DAA_TARGET) == FeatureState.LOCKED_IN
        assert state(16, Feature.REDUCE_DAA_TARGET) == FeatureState.ACTIVE
        assert state(31, Feature.RESTORE_DAA_TARGET) == FeatureState.LOCKED_IN
        assert state(32, Feature.RESTORE_DAA_TARGET) == FeatureState.ACTIVE
        assert state(40, Feature.REDUCE_DAA_TARGET) == FeatureState.ACTIVE

        # Shape B on both boundaries: the activation block keeps the previous era's rules.
        assert by_height[16].sum_outputs == self.v1_reward
        assert by_height[17].sum_outputs == self.v2_reward
        assert by_height[32].sum_outputs == self.v2_reward
        assert by_height[33].sum_outputs == self.v1_reward

        self._assert_consistent_history(manager)

    def test_rejects_wrong_reward_on_each_side_of_restore(self) -> None:
        manager, _ = self._create_manager()
        verifier = manager.verification_service.verifiers.block

        def tampered_child(parent_height: int, reward: int) -> Block:
            parent = manager.tx_storage.get_block_by_height(parent_height)
            assert parent is not None
            block = manager.generate_mining_block(parent_block_hash=parent.hash)
            block.outputs[0].value = reward
            return block

        add_new_blocks(manager, RESTORE_ACTIVATION_HEIGHT + 1, signal_bits=0b11)
        # The activation block (32) is still V2: a full reward is invalid.
        with pytest.raises(InvalidBlockReward):
            verifier.verify_reward(tampered_child(RESTORE_ACTIVATION_HEIGHT - 1, self.v1_reward))
        verifier.verify_reward(tampered_child(RESTORE_ACTIVATION_HEIGHT - 1, self.v2_reward))
        # The first V3 block (33) must have the full reward: a reduced reward is invalid.
        with pytest.raises(InvalidBlockReward):
            verifier.verify_reward(tampered_child(RESTORE_ACTIVATION_HEIGHT, self.v2_reward))
        verifier.verify_reward(tampered_child(RESTORE_ACTIVATION_HEIGHT, self.v1_reward))

        # And a reduced-reward V3 block is not accepted by the node.
        block = tampered_child(RESTORE_ACTIVATION_HEIGHT + 1, self.v2_reward)
        manager.cpu_mining_service.resolve(block)
        with pytest.raises(InvalidNewTransaction, match='invalid_issued_tokens'):
            manager.propagate_tx(block)
        with pytest.raises(TransactionDoesNotExist):
            manager.tx_storage.get_transaction(block.hash)

    def test_fresh_node_syncs_and_verifies_full_history(self) -> None:
        manager1, _ = self._create_manager()
        add_new_blocks(manager1, 60, signal_bits=0b11)

        manager2, _ = self._create_manager()
        conn = FakeConnection(manager1, manager2, latency=0.1)
        self.simulator.add_connection(conn)
        self.simulator.run(600)

        assert manager2.tx_storage.get_best_block().hash == manager1.tx_storage.get_best_block().hash
        self.assertConsensusEqual(manager1, manager2)
        self._assert_consistent_history(manager2)

    def test_reorg_across_restore_boundary(self) -> None:
        manager1, _ = self._create_manager()
        manager2, _ = self._create_manager()
        conn = FakeConnection(manager1, manager2, latency=0.1)
        self.simulator.add_connection(conn)

        # Common history up to LOCKED_IN, before the RESTORE activation boundary.
        add_new_blocks(manager1, 28, signal_bits=0b11)
        self.simulator.run(60)
        assert manager2.tx_storage.get_best_block().hash == manager1.tx_storage.get_best_block().hash

        # Fork across the activation boundary; manager2's branch is longer and must win.
        conn.disconnect(Failure(Exception('fork')))
        self.simulator.remove_connection(conn)
        add_new_blocks(manager1, 8, signal_bits=0b11)
        add_new_blocks(manager2, 12, signal_bits=0b11)
        assert manager1.tx_storage.get_best_block().hash != manager2.tx_storage.get_best_block().hash
        conn.reconnect()
        self.simulator.add_connection(conn)
        self.simulator.run(600)

        best = manager1.tx_storage.get_best_block()
        assert best.hash == manager2.tx_storage.get_best_block().hash
        assert best.get_height() == 40
        self.assertConsensusEqual(manager1, manager2)
        self._assert_consistent_history(manager1)
        self._assert_consistent_history(manager2)
