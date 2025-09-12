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

from hathor.conf.settings import NanoContractsSetting
from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.types import BlueprintId
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from tests import unittest
from tests.dag_builder.builder import TestDAGBuilder


class MyBluprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass


class TestNanoFeatureActivation(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.NANO_CONTRACTS: Criteria(
                    bit=2,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0'
                )
            }
        )

        settings = self._settings._replace(
            ENABLE_NANO_CONTRACTS=NanoContractsSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        )
        daa = DifficultyAdjustmentAlgorithm(settings=self._settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)

        self.manager = self.create_peer_from_builder(builder)
        self.vertex_handler = self.manager.vertex_handler
        self.feature_service = self.manager.feature_service
        self.bit_signaling_service = self.manager._bit_signaling_service
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

        self.blueprint_id = BlueprintId(self.rng.randbytes(32))
        assert self.manager.tx_storage.nc_catalog is not None
        self.manager.tx_storage.nc_catalog.blueprints[self.blueprint_id] = MyBluprint

    def test_activation(self) -> None:
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            blockchain b10 a[11..12]
            b10 < dummy < b11

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = test_blueprint1.py, TestBlueprint1

            b12 < nc1 < ocb1

            nc1 <-- b13
            ocb1 <-- b13

            a11.weight = 10
            b13 < a11
        ''')

        b3, b4, b7, b8, b11, b12, b13, a11 = artifacts.get_typed_vertices(
            ('b3', 'b4', 'b7', 'b8', 'b11', 'b12', 'b13', 'a11'),
            Block,
        )
        nc1, ocb1 = artifacts.get_typed_vertices(('nc1', 'ocb1'), Transaction)

        artifacts.propagate_with(self.manager, up_to='b3')
        assert self.feature_service.get_state(block=b3, feature=Feature.NANO_CONTRACTS) is FeatureState.DEFINED

        artifacts.propagate_with(self.manager, up_to='b4')
        assert self.feature_service.get_state(block=b4, feature=Feature.NANO_CONTRACTS) is FeatureState.STARTED

        signaling_blocks = ('b5', 'b6', 'b7')
        for block_name in signaling_blocks:
            block = artifacts.by_name[block_name].vertex
            assert isinstance(block, Block)
            block.storage = self.manager.tx_storage
            block.signal_bits = self.bit_signaling_service.generate_signal_bits(block=block.get_block_parent())
            artifacts.propagate_with(self.manager, up_to=block_name)

        assert self.feature_service.get_state(block=b7, feature=Feature.NANO_CONTRACTS) is FeatureState.STARTED

        artifacts.propagate_with(self.manager, up_to='b8')
        assert self.feature_service.get_state(block=b8, feature=Feature.NANO_CONTRACTS) is FeatureState.LOCKED_IN

        artifacts.propagate_with(self.manager, up_to='b11')
        assert self.feature_service.get_state(block=b11, feature=Feature.NANO_CONTRACTS) is FeatureState.LOCKED_IN

        # At this point, the feature is not active, so the nc txs are rejected on the mempool.
        msg = 'full validation failed: Header `NanoHeader` not supported by `Transaction`'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(nc1)
        assert nc1.get_metadata().validation.is_initial()
        assert nc1.get_metadata().voided_by is None

        msg = 'full validation failed: invalid vertex version: 6'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(ocb1)
        assert ocb1.get_metadata().validation.is_initial()
        assert ocb1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.NANO_CONTRACTS) is FeatureState.ACTIVE

        # Now, the nc txs are accepted on the mempool.
        artifacts.propagate_with(self.manager, up_to='nc1')
        assert nc1.get_metadata().validation.is_valid()
        assert nc1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='ocb1')
        assert ocb1.get_metadata().validation.is_valid()
        assert ocb1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b13')
        assert nc1.get_metadata().nc_execution is NCExecutionState.SUCCESS

        artifacts.propagate_with(self.manager, up_to='a11')
        assert a11.get_metadata().validation.is_valid()
        assert a11.get_metadata().voided_by is None
        assert b12.get_metadata().voided_by == {b12.hash}
        assert b13.get_metadata().validation.is_invalid()
        assert ocb1.get_metadata().validation.is_invalid()
        assert ocb1.get_metadata().validation.is_invalid()

        # The nc txs are removed from the mempool.
        assert not self.manager.tx_storage.transaction_exists(b13.hash)
        assert not self.manager.tx_storage.transaction_exists(nc1.hash)
        assert not self.manager.tx_storage.transaction_exists(ocb1.hash)
        assert nc1 not in list(self.manager.tx_storage.iter_mempool_tips_from_best_index())
        assert ocb1 not in list(self.manager.tx_storage.iter_mempool_tips_from_best_index())

        # The nc txs are re-accepted on the mempool.
        artifacts.propagate_with(self.manager, up_to='a12')

        nc1._metadata = None
        self.vertex_handler.on_new_relayed_vertex(nc1)
        assert nc1.get_metadata().validation.is_valid()
        assert nc1.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(nc1.hash)
        assert nc1 in list(self.manager.tx_storage.iter_mempool_tips_from_best_index())

        ocb1._metadata = None
        self.vertex_handler.on_new_relayed_vertex(ocb1)
        assert ocb1.get_metadata().validation.is_valid()
        assert ocb1.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(ocb1.hash)
        assert ocb1 in list(self.manager.tx_storage.iter_mempool_tips_from_best_index())
