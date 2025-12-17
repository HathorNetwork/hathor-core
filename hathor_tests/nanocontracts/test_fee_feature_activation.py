#  Copyright 2025 Hathor Labs
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

import pytest

from hathor.conf.settings import FeatureSettingEnum
from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TestFeeFeatureActivation(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.FEE_TOKENS: Criteria(
                    bit=3,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0'
                )
            }
        )

        settings = self._settings._replace(
            ENABLE_FEE=FeatureSettingEnum.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        )
        daa = DifficultyAdjustmentAlgorithm(settings=self._settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)

        self.manager = self.create_peer_from_builder(builder)
        self.vertex_handler = self.manager.vertex_handler
        self.feature_service = self.manager.feature_service
        self.bit_signaling_service = self.manager._bit_signaling_service
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_fee_activation(self) -> None:
        """Test that fee feature activation works correctly through the feature activation process."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy < b11

            FBT.token_version = fee
            FBT.fee = 1 HTR

            tx1.out[0] = 123 FBT
            tx1.fee = 1 HTR

            b12 < FBT < tx1 < b13
        ''')

        b3, b4, b7, b8, b11, b12, b13 = artifacts.get_typed_vertices(
            ('b3', 'b4', 'b7', 'b8', 'b11', 'b12', 'b13'),
            Block,
        )
        fbt, tx1 = artifacts.get_typed_vertices(('FBT', 'tx1'), Transaction)

        artifacts.propagate_with(self.manager, up_to='b3')
        assert self.feature_service.get_state(block=b3, feature=Feature.FEE_TOKENS) == FeatureState.DEFINED

        artifacts.propagate_with(self.manager, up_to='b4')
        assert self.feature_service.get_state(block=b4, feature=Feature.FEE_TOKENS) == FeatureState.STARTED

        signaling_blocks = ('b5', 'b6', 'b7')
        for block_name in signaling_blocks:
            block = artifacts.by_name[block_name].vertex
            assert isinstance(block, Block)
            block.storage = self.manager.tx_storage
            block.signal_bits = self.bit_signaling_service.generate_signal_bits(block=block.get_block_parent())
            artifacts.propagate_with(self.manager, up_to=block_name)

        assert self.feature_service.get_state(block=b7, feature=Feature.FEE_TOKENS) == FeatureState.STARTED

        artifacts.propagate_with(self.manager, up_to='b8')
        assert self.feature_service.get_state(block=b8, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN

        artifacts.propagate_with(self.manager, up_to='b11')
        assert self.feature_service.get_state(block=b11, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN

        # At this point, the fee feature is not active, so the fee txs are rejected on the mempool.
        msg = 'full validation failed: Header `FeeHeader` not supported by'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(fbt)
        assert fbt.get_metadata().validation.is_initial()
        assert fbt.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.FEE_TOKENS) == FeatureState.ACTIVE

        # Now, the fee txs are accepted on the mempool.
        artifacts.propagate_with(self.manager, up_to='FBT')
        assert fbt.get_metadata().validation.is_valid()
        assert fbt.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='tx1')
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b13')
        assert b13.get_metadata().validation.is_valid()
        assert b13.get_metadata().voided_by is None

    def test_fee_disabled(self) -> None:
        """Test that fee txs are rejected when fee is disabled."""
        # Override settings to disable fee
        settings = self._settings._replace(ENABLE_FEE=FeatureSettingEnum.DISABLED)
        daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)

        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        # Need at least 11 blocks to unlock rewards (REWARD_SPEND_MIN_BLOCKS=10)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy < b11

            FBT.token_version = fee
            FBT.fee = 1 HTR

            b12 < FBT
        ''')

        fbt = artifacts.get_typed_vertex('FBT', Transaction)

        artifacts.propagate_with(manager, up_to='b12')

        # Fee txs are rejected because fee is disabled
        msg = 'full validation failed: Header `FeeHeader` not supported by'
        with pytest.raises(InvalidNewTransaction, match=msg):
            manager.vertex_handler.on_new_relayed_vertex(fbt)
        assert fbt.get_metadata().validation.is_initial()

    def test_fee_enabled(self) -> None:
        """Test that fee txs are accepted when fee is always enabled."""
        # Override settings to always enable fee
        settings = self._settings._replace(ENABLE_FEE=FeatureSettingEnum.ENABLED)
        daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)

        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        # Need at least 11 blocks to unlock rewards (REWARD_SPEND_MIN_BLOCKS=10)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy < b11

            FBT.token_version = fee
            FBT.fee = 1 HTR

            tx1.out[0] = 123 FBT
            tx1.fee = 1 HTR

            b12 < FBT < tx1
        ''')

        fbt, tx1 = artifacts.get_typed_vertices(('FBT', 'tx1'), Transaction)

        artifacts.propagate_with(manager, up_to='b12')

        # Fee txs are accepted because fee is always enabled
        artifacts.propagate_with(manager, up_to='FBT')
        assert fbt.get_metadata().validation.is_valid()
        assert fbt.get_metadata().voided_by is None

        artifacts.propagate_with(manager, up_to='tx1')
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None
