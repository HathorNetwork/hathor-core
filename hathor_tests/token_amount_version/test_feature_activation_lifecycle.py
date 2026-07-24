# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""The `TOKEN_AMOUNT_V2` feature-activation lifecycle and its end-to-end (manager-level) effect on V2 acceptance.

The feature is gated two ways that combine in `Features.from_vertex`: the per-network `ENABLE_TOKEN_AMOUNT_V2`
setting (`DISABLED` / `ENABLED` / `FEATURE_ACTIVATION`) and, under `FEATURE_ACTIVATION`, the best block's feature
state (`DEFINED` -> `STARTED` -> `LOCKED_IN` -> `ACTIVE`). A V2 token amount is only allowed once the feature is
active for the best block, so a V2 tx relayed on the mempool is accepted exactly when the best block is `ACTIVE`,
while V1 traffic is accepted at every state. These tests drive the state machine by mining through the
evaluation-interval boundaries (setting the signal bits on the blocks of the locking interval) and relay V1/V2
txs through the manager at each state. The `ENABLE_TOKEN_AMOUNT_V2` setting short-circuits the state machine:
when `DISABLED`, the feature reports inactive even at an `ACTIVE` block state.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from hathor.conf.settings import HathorSettings
from hathor.daa import DAAFactory, DAAVersion, TestMode
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.feature_activation.utils import Features
from hathor.nanocontracts.nano_runtime_version import NanoRuntimeVersion
from hathor.transaction import Block, Transaction
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.conf import (
    MAINNET_SETTINGS_FILEPATH,
    NANO_TESTNET_SETTINGS_FILEPATH,
    TESTNET_INDIA_SETTINGS_FILEPATH,
    UNITTESTS_SETTINGS_FILEPATH,
)
from hathorlib.conf.settings import FeatureSetting
from hathorlib.conf.utils import load_yaml_settings
from hathorlib.token_amount_version import TokenAmountVersion

if TYPE_CHECKING:
    from hathor.dag_builder.artifacts import DAGArtifacts

# A chain long enough to carry `TOKEN_AMOUNT_V2` from DEFINED to ACTIVE under the criteria below, plus a single
# V2 tx that spends `b1`'s entire block reward as one input (so it is self-funded and can be relayed on the
# mempool without a separately-propagated funding tx) and is ordered after the last block so it is only ever
# relayed by hand, never auto-propagated with the chain.
_V2_TX_DAG = '''
    blockchain genesis b[1..13]

    b1.out[0] = 64.00 HTR
    b1.out[0] <<< tx_v2
    tx_v2.out[0] = 1.00 HTR
    tx_v2.token_amount_version = V2

    b13 < tx_v2
'''


class TestFeatureActivationLifecycle(unittest.TestCase):
    def _lifecycle_settings(self, token_amount_v2_setting: FeatureSetting) -> HathorSettings:
        """Settings that put `TOKEN_AMOUNT_V2` on a short feature-activation schedule.

        Block rewards mature immediately (`REWARD_SPEND_MIN_BLOCKS=0`) so a tx spending an early block can be
        relayed at any best-block height, including the pre-activation states.
        """
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.TOKEN_AMOUNT_V2: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0',
                ),
            },
        )
        return self._settings.model_copy(update=dict(
            ENABLE_TOKEN_AMOUNT_V2=token_amount_v2_setting,
            REWARD_SPEND_MIN_BLOCKS=0,
            FEATURE_ACTIVATION=feature_settings,
        ))

    def _prepare(self, settings: HathorSettings) -> None:
        daa_factory = DAAFactory(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa_factory(daa_factory)
        self.manager = self.create_peer_from_builder(builder)
        self.feature_service = self.manager.feature_service
        self.vertex_handler = self.manager.vertex_handler
        self.bit_signaling_service = self.manager._bit_signaling_service
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _propagate_signaling(self, artifacts: DAGArtifacts) -> None:
        """Propagate the blocks of the interval [b5, b7], each signaling support so the feature locks in at b8."""
        for block_name in ('b5', 'b6', 'b7'):
            block = artifacts.by_name[block_name].vertex
            assert isinstance(block, Block)
            block.storage = self.manager.tx_storage
            block.signal_bits = self.bit_signaling_service.generate_signal_bits(block=block.get_block_parent())
            artifacts.propagate_with(self.manager, up_to=block_name)

    def _propagate_to_active(self, artifacts: DAGArtifacts) -> None:
        """Mine through every boundary until `TOKEN_AMOUNT_V2` is ACTIVE, leaving b12 as the best block."""
        artifacts.propagate_with(self.manager, up_to='b4')
        self._propagate_signaling(artifacts)
        artifacts.propagate_with(self.manager, up_to='b12')

    def test_setting_default_disabled_on_all_real_networks(self) -> None:
        """Build mainnet/testnet/production settings (no override) and assert `ENABLE_TOKEN_AMOUNT_V2` is DISABLED.
        Pins that V2 ships gated OFF everywhere real."""
        for filepath in (MAINNET_SETTINGS_FILEPATH, TESTNET_INDIA_SETTINGS_FILEPATH, NANO_TESTNET_SETTINGS_FILEPATH):
            settings = load_yaml_settings(HathorSettings, filepath=filepath)
            assert settings.ENABLE_TOKEN_AMOUNT_V2 == FeatureSetting.DISABLED

    def test_unittests_yml_enables_feature(self) -> None:
        """Assert the unittest settings set `ENABLE_TOKEN_AMOUNT_V2` to ENABLED. Pins the test-suite-wide default
        (so inactive-path tests must explicitly override it)."""
        settings = load_yaml_settings(HathorSettings, filepath=UNITTESTS_SETTINGS_FILEPATH)
        assert settings.ENABLE_TOKEN_AMOUNT_V2 == FeatureSetting.ENABLED

    def test_disabled_setting_overrides_state_machine(self) -> None:
        """With the setting DISABLED, assert the feature reports inactive even for an ACTIVE block state, end-to-end:
        V2 txs are rejected at every height. Pins the DISABLED short-circuit."""
        self._prepare(self._lifecycle_settings(FeatureSetting.DISABLED))
        artifacts = self.dag_builder.build_from_str(_V2_TX_DAG)
        b3, b12 = artifacts.get_typed_vertices(('b3', 'b12'), Block)
        tx_v2, = artifacts.get_typed_vertices(('tx_v2',), Transaction)

        # A V2 tx is rejected while the state is still DEFINED.
        artifacts.propagate_with(self.manager, up_to='b3')
        assert self.feature_service.get_state(block=b3, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.DEFINED
        with pytest.raises(InvalidNewTransaction, match=re.escape('invalid token amount version: V2')):
            self.vertex_handler.on_new_relayed_vertex(tx_v2)

        # The state machine drives the feature to ACTIVE, but the DISABLED setting keeps it inactive.
        artifacts.propagate_with(self.manager, up_to='b4')
        self._propagate_signaling(artifacts)
        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE

        features_b12 = Features.from_vertex(
            settings=self.manager._settings, feature_service=self.feature_service, vertex=b12,
        )
        assert features_b12.token_amount_version == TokenAmountVersion.V1

        # The same V2 tx is still rejected at the ACTIVE block state.
        with pytest.raises(InvalidNewTransaction, match=re.escape('invalid token amount version: V2')):
            self.vertex_handler.on_new_relayed_vertex(tx_v2)
        assert tx_v2.get_metadata().validation.is_initial()
        assert tx_v2.get_metadata().voided_by is None
        assert not self.manager.tx_storage.transaction_exists(tx_v2.hash)

    def test_features_carries_token_amount_version_field(self) -> None:
        """Assert `Features.from_vertex(block).token_amount_version` is V2 when the feature is active for that block
        and V1 otherwise, and that constructing `Features(...)` without the field raises (every call site must set
        it). Pins the new permissive feature field."""
        self._prepare(self._lifecycle_settings(FeatureSetting.FEATURE_ACTIVATION))
        artifacts = self.dag_builder.build_from_str(_V2_TX_DAG)
        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        self._propagate_to_active(artifacts)

        # b11 is LOCKED_IN (feature inactive) -> V1; b12 is ACTIVE (feature active) -> V2.
        assert self.feature_service.get_state(block=b11, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.LOCKED_IN
        assert self.feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE

        features_b11 = Features.from_vertex(
            settings=self.manager._settings, feature_service=self.feature_service, vertex=b11,
        )
        features_b12 = Features.from_vertex(
            settings=self.manager._settings, feature_service=self.feature_service, vertex=b12,
        )
        assert features_b11.token_amount_version == TokenAmountVersion.V1
        assert features_b12.token_amount_version == TokenAmountVersion.V2

        # The field has no default, so every construction site must provide it.
        with pytest.raises(
            TypeError,
            match=re.escape("missing 1 required keyword-only argument: 'token_amount_version'"),
        ):
            Features(  # type: ignore[call-arg]
                count_checkdatasig_op=True,
                nanocontracts=True,
                fee_tokens=True,
                opcodes_version=OpcodesVersion.V2,
                nano_runtime_version=NanoRuntimeVersion.V2,
                restrict_dup_actions=True,
                daa_version=DAAVersion.V2,
                shielded_transactions=True,
            )

    def test_lifecycle_transitions_to_active(self) -> None:
        """With FEATURE_ACTIVATION criteria, mine through the boundaries and assert the feature state progresses
        DEFINED -> STARTED -> LOCKED_IN -> ACTIVE at the expected blocks. Mirrors other features' lifecycle tests."""
        self._prepare(self._lifecycle_settings(FeatureSetting.FEATURE_ACTIVATION))
        artifacts = self.dag_builder.build_from_str(_V2_TX_DAG)
        b3, b4, b8, b11, b12 = artifacts.get_typed_vertices(('b3', 'b4', 'b8', 'b11', 'b12'), Block)

        artifacts.propagate_with(self.manager, up_to='b3')
        assert self.feature_service.get_state(block=b3, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.DEFINED

        artifacts.propagate_with(self.manager, up_to='b4')
        assert self.feature_service.get_state(block=b4, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.STARTED

        self._propagate_signaling(artifacts)
        artifacts.propagate_with(self.manager, up_to='b8')
        assert self.feature_service.get_state(block=b8, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.LOCKED_IN

        artifacts.propagate_with(self.manager, up_to='b11')
        assert self.feature_service.get_state(block=b11, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.LOCKED_IN

        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE

    def test_v2_tx_rejected_before_activation_via_manager(self) -> None:
        """While the best block state is pre-ACTIVE, relay a V2 tx through the manager and assert it is rejected
        (wrapping `invalid token amount version: V2`), stays initial, and is not voided/stored. End-to-end reject."""
        self._prepare(self._lifecycle_settings(FeatureSetting.FEATURE_ACTIVATION))
        artifacts = self.dag_builder.build_from_str(_V2_TX_DAG)
        b4, = artifacts.get_typed_vertices(('b4',), Block)
        tx_v2, = artifacts.get_typed_vertices(('tx_v2',), Transaction)

        artifacts.propagate_with(self.manager, up_to='b4')
        assert self.feature_service.get_state(block=b4, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.STARTED

        with pytest.raises(InvalidNewTransaction, match=re.escape('invalid token amount version: V2')):
            self.vertex_handler.on_new_relayed_vertex(tx_v2)
        assert tx_v2.get_metadata().validation.is_initial()
        assert tx_v2.get_metadata().voided_by is None
        assert not self.manager.tx_storage.transaction_exists(tx_v2.hash)

    def test_v2_tx_accepted_after_activation_via_manager(self) -> None:
        """Once the best block reaches ACTIVE, relay/propagate the same V2 tx and assert it is valid, not voided,
        stored, and appears among mempool tips. End-to-end accept."""
        self._prepare(self._lifecycle_settings(FeatureSetting.FEATURE_ACTIVATION))
        artifacts = self.dag_builder.build_from_str(_V2_TX_DAG)
        b12, = artifacts.get_typed_vertices(('b12',), Block)
        tx_v2, = artifacts.get_typed_vertices(('tx_v2',), Transaction)

        self._propagate_to_active(artifacts)
        assert self.feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE

        self.vertex_handler.on_new_relayed_vertex(tx_v2)
        assert tx_v2.get_metadata().validation.is_valid()
        assert tx_v2.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(tx_v2.hash)
        assert tx_v2 in list(self.manager.tx_storage.iter_mempool_tips())

    def test_v1_tx_accepted_throughout_lifecycle(self) -> None:
        """Relay a V1 tx at DEFINED, STARTED, LOCKED_IN, and ACTIVE best-block states; assert it is accepted at
        every stage. Pins that the lifecycle never blocks V1 traffic."""
        self._prepare(self._lifecycle_settings(FeatureSetting.FEATURE_ACTIVATION))
        # Four independent, self-funded V1 txs, one per lifecycle state, each ordered after the last block so it is
        # only ever relayed by hand.
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]

            b1.out[0] = 64.00 HTR
            b1.out[0] <<< tx_defined
            tx_defined.out[0] = 1.00 HTR
            b13 < tx_defined

            b2.out[0] = 64.00 HTR
            b2.out[0] <<< tx_started
            tx_started.out[0] = 1.00 HTR
            b13 < tx_started

            b3.out[0] = 64.00 HTR
            b3.out[0] <<< tx_locked
            tx_locked.out[0] = 1.00 HTR
            b13 < tx_locked

            b4.out[0] = 64.00 HTR
            b4.out[0] <<< tx_active
            tx_active.out[0] = 1.00 HTR
            b13 < tx_active
        ''')
        b3, b4, b8, b12 = artifacts.get_typed_vertices(('b3', 'b4', 'b8', 'b12'), Block)
        tx_defined, tx_started, tx_locked, tx_active = artifacts.get_typed_vertices(
            ('tx_defined', 'tx_started', 'tx_locked', 'tx_active'), Transaction,
        )

        artifacts.propagate_with(self.manager, up_to='b3')
        assert self.feature_service.get_state(block=b3, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.DEFINED
        self.vertex_handler.on_new_relayed_vertex(tx_defined)
        assert tx_defined.get_metadata().validation.is_valid()
        assert tx_defined.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b4')
        assert self.feature_service.get_state(block=b4, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.STARTED
        self.vertex_handler.on_new_relayed_vertex(tx_started)
        assert tx_started.get_metadata().validation.is_valid()
        assert tx_started.get_metadata().voided_by is None

        self._propagate_signaling(artifacts)
        artifacts.propagate_with(self.manager, up_to='b8')
        assert self.feature_service.get_state(block=b8, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.LOCKED_IN
        self.vertex_handler.on_new_relayed_vertex(tx_locked)
        assert tx_locked.get_metadata().validation.is_valid()
        assert tx_locked.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE
        self.vertex_handler.on_new_relayed_vertex(tx_active)
        assert tx_active.get_metadata().validation.is_valid()
        assert tx_active.get_metadata().voided_by is None

    def test_relayed_v2_tx_accepted_exactly_when_best_block_active(self) -> None:
        """Propagate to the first ACTIVE best block and assert a relayed V2 tx is accepted, while one block earlier
        (best block LOCKED_IN) the same tx is rejected. Pins the exact activation boundary for the mempool path."""
        self._prepare(self._lifecycle_settings(FeatureSetting.FEATURE_ACTIVATION))
        artifacts = self.dag_builder.build_from_str(_V2_TX_DAG)
        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx_v2, = artifacts.get_typed_vertices(('tx_v2',), Transaction)

        # One block before activation: best block b11 is LOCKED_IN, so the V2 tx is rejected.
        artifacts.propagate_with(self.manager, up_to='b4')
        self._propagate_signaling(artifacts)
        artifacts.propagate_with(self.manager, up_to='b11')
        assert self.feature_service.get_state(block=b11, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.LOCKED_IN
        with pytest.raises(InvalidNewTransaction, match=re.escape('invalid token amount version: V2')):
            self.vertex_handler.on_new_relayed_vertex(tx_v2)
        assert tx_v2.get_metadata().validation.is_initial()
        assert not self.manager.tx_storage.transaction_exists(tx_v2.hash)

        # The first ACTIVE best block b12: the same V2 tx is now accepted.
        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE
        self.vertex_handler.on_new_relayed_vertex(tx_v2)
        assert tx_v2.get_metadata().validation.is_valid()
        assert tx_v2.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(tx_v2.hash)
        assert tx_v2 in list(self.manager.tx_storage.iter_mempool_tips())
