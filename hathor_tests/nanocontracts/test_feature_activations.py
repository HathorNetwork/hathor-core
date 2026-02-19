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

from hathor.conf.settings import FeatureSetting
from hathor.crypto.util import decode_address, get_address_from_public_key_hash
from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.types import BlueprintId
from hathor.transaction import Block, Transaction, Vertex
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.scripts import P2PKH, Opcode
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class MyBluprint(Blueprint):
    a: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.a = 123

    @public
    def nop(self, ctx: Context) -> None:
        self.a = 456


class TestNanoFeatureActivation(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.OPCODES_V2: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0'
                ),
                Feature.NANO_CONTRACTS: Criteria(
                    bit=1,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0'
                ),
                Feature.FEE_TOKENS: Criteria(
                    bit=2,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0'
                )
            }
        )

        settings = self._settings.model_copy(update={
            'ENABLE_NANO_CONTRACTS': FeatureSetting.FEATURE_ACTIVATION,
            'ENABLE_FEE_BASED_TOKENS': FeatureSetting.FEATURE_ACTIVATION,
            'ENABLE_OPCODES_V2': FeatureSetting.FEATURE_ACTIVATION,
            'FEATURE_ACTIVATION': feature_settings,
        })
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

        empty_block_storage = self.manager.consensus_algorithm.nc_storage_factory.get_empty_block_storage()
        empty_block_storage.commit()
        self.empty_root_id = empty_block_storage.get_root_id()

    async def test_activation(self) -> None:
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            blockchain b10 a[11..13]
            b10 < dummy < b11

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = test_blueprint1.py, TestBlueprint1

            FBT.token_version = fee
            FBT.fee = 1 HTR

            fee_tx.out[0] = 123 FBT
            fee_tx.fee = 1 HTR

            op_v2_a.out[0] <<< op_v2_b
            op_v2_b <-- b11

            b10 < op_v2_a < op_v2_b < b11 < b12 < nc1 < ocb1 < FBT < fee_tx < b13 < a11

            nc1 <-- b13
            ocb1 <-- b13

            a11.weight = 20

            nc1 <-- a13
            ocb1 <-- a13
        ''')

        b3, b4, b7, b8, b11, b12, b13, a11, a12, a13 = artifacts.get_typed_vertices(
            ('b3', 'b4', 'b7', 'b8', 'b11', 'b12', 'b13', 'a11', 'a12', 'a13'),
            Block,
        )
        nc1, ocb1, fbt, fee_tx, op_v2_a, op_v2_b = artifacts.get_typed_vertices(
            ('nc1', 'ocb1', 'FBT', 'fee_tx', 'op_v2_a', 'op_v2_b'),
            Transaction,
        )

        # Setup txs for testing OPCODES_V2.
        assert len(op_v2_b.outputs) == 1
        op_v2_b_out = op_v2_b.outputs[0]
        p2pkh = P2PKH.parse_script(op_v2_b_out.script)
        assert p2pkh is not None
        op_v2_address = decode_address(p2pkh.address)

        # This is a custom script that uses one of the deprecated opcodes and will end with 1 on the stack.
        assert len(op_v2_b.inputs) == 1
        op_v2_b_in = op_v2_b.inputs[0]
        op_v2_b_in.data = bytes([
            0x19,
            *get_address_from_public_key_hash(op_v2_address[1:-4]),
            Opcode.OP_FIND_P2PKH,
        ])

        assert op_v2_b_in.tx_id == op_v2_a.hash
        op_v2_a_out = op_v2_a.outputs[op_v2_b_in.index]
        op_v2_a_out.script = b''  # Empty script so op_v2_b can spend it with the custom script.

        artifacts.propagate_with(self.manager, up_to='b3')
        assert self.feature_service.get_state(block=b3, feature=Feature.NANO_CONTRACTS) == FeatureState.DEFINED
        assert self.feature_service.get_state(block=b3, feature=Feature.FEE_TOKENS) == FeatureState.DEFINED
        assert self.feature_service.get_state(block=b3, feature=Feature.OPCODES_V2) == FeatureState.DEFINED

        artifacts.propagate_with(self.manager, up_to='b4')
        assert self.feature_service.get_state(block=b4, feature=Feature.NANO_CONTRACTS) == FeatureState.STARTED
        assert self.feature_service.get_state(block=b4, feature=Feature.FEE_TOKENS) == FeatureState.STARTED
        assert self.feature_service.get_state(block=b4, feature=Feature.OPCODES_V2) == FeatureState.STARTED

        signaling_blocks = ('b5', 'b6', 'b7')
        for block_name in signaling_blocks:
            block = artifacts.by_name[block_name].vertex
            assert isinstance(block, Block)
            block.storage = self.manager.tx_storage
            block.signal_bits = self.bit_signaling_service.generate_signal_bits(block=block.get_block_parent())
            artifacts.propagate_with(self.manager, up_to=block_name)

        assert self.feature_service.get_state(block=b7, feature=Feature.NANO_CONTRACTS) == FeatureState.STARTED
        assert self.feature_service.get_state(block=b7, feature=Feature.FEE_TOKENS) == FeatureState.STARTED
        assert self.feature_service.get_state(block=b7, feature=Feature.OPCODES_V2) == FeatureState.STARTED

        artifacts.propagate_with(self.manager, up_to='b8')
        assert self.feature_service.get_state(block=b8, feature=Feature.NANO_CONTRACTS) == FeatureState.LOCKED_IN
        assert self.feature_service.get_state(block=b8, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN
        assert self.feature_service.get_state(block=b8, feature=Feature.OPCODES_V2) == FeatureState.LOCKED_IN

        artifacts.propagate_with(self.manager, up_to='op_v2_a')

        # At this point the OPCODES_V2 feature is not active,
        # but deprecated opcodes are already rejected on the mempool
        msg = 'full validation failed: unknown opcode: 208'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(op_v2_b)
        assert op_v2_b.get_metadata().validation.is_initial()
        assert op_v2_b.get_metadata().voided_by is None

        # However, deprecated opcodes would be accepted if relayed inside a block.
        # We have to manually propagate it.
        d = self.vertex_handler.on_new_block(b11, deps=[op_v2_b])
        self.clock.advance(1)
        assert d.called and d.result is True
        artifacts._last_propagated = 'b11'

        assert self.feature_service.get_state(block=b11, feature=Feature.NANO_CONTRACTS) == FeatureState.LOCKED_IN
        assert self.feature_service.get_state(block=b11, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN
        assert self.feature_service.get_state(block=b11, feature=Feature.OPCODES_V2) == FeatureState.LOCKED_IN

        assert b11.get_metadata().nc_block_root_id == self.empty_root_id

        # At this point the nano feature is not active, so nano header is rejected on the mempool
        msg = 'full validation failed: Header `NanoHeader` not supported by `Transaction`'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(nc1)
        assert nc1.get_metadata().validation.is_initial()
        assert nc1.get_metadata().voided_by is None

        # At this point the nano feature is not active, so OCB is rejected on the mempool
        msg = 'full validation failed: invalid vertex version: 6'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(ocb1)
        assert ocb1.get_metadata().validation.is_initial()
        assert ocb1.get_metadata().voided_by is None

        # At this point the fee feature is not active, so fee header is rejected on the mempool
        msg = 'full validation failed: Header `FeeHeader` not supported by `TokenCreationTransaction`'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(fbt)
        assert fbt.get_metadata().validation.is_initial()
        assert fbt.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.NANO_CONTRACTS) == FeatureState.ACTIVE
        assert self.feature_service.get_state(block=b12, feature=Feature.FEE_TOKENS) == FeatureState.ACTIVE
        assert self.feature_service.get_state(block=b12, feature=Feature.OPCODES_V2) == FeatureState.ACTIVE

        assert b11.get_metadata().nc_block_root_id == self.empty_root_id
        assert b12.get_metadata().nc_block_root_id == self.empty_root_id

        # Now, the nc and fee txs are accepted on the mempool.
        artifacts.propagate_with(self.manager, up_to='nc1')
        assert nc1.get_metadata().validation.is_valid()
        assert nc1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='ocb1')
        assert ocb1.get_metadata().validation.is_valid()
        assert ocb1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='FBT')
        assert fbt.get_metadata().validation.is_valid()
        assert fbt.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='fee_tx')
        assert fee_tx.get_metadata().validation.is_valid()
        assert fee_tx.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b13')
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        assert b11.get_metadata().nc_block_root_id == self.empty_root_id
        assert b12.get_metadata().nc_block_root_id == self.empty_root_id
        assert b13.get_metadata().nc_block_root_id not in (self.empty_root_id, None)

        # A reorg happens, decreasing the best chain.
        artifacts.propagate_with(self.manager, up_to='a11')
        assert a11.get_metadata().validation.is_valid()
        assert a11.get_metadata().voided_by is None
        assert b11.get_metadata().validation.is_invalid()
        assert b12.get_metadata().validation.is_invalid()
        assert b13.get_metadata().validation.is_invalid()
        assert nc1.get_metadata().validation.is_invalid()
        assert ocb1.get_metadata().validation.is_invalid()
        assert fbt.get_metadata().validation.is_invalid()
        assert fee_tx.get_metadata().validation.is_invalid()
        assert op_v2_b.get_metadata().validation.is_invalid()

        assert b11.get_metadata().nc_block_root_id == self.empty_root_id
        assert b12.get_metadata().nc_block_root_id == self.empty_root_id
        assert b13.get_metadata().nc_block_root_id not in (self.empty_root_id, None)
        assert a11.get_metadata().nc_block_root_id == self.empty_root_id

        # The nc, fee, and deprecated opcodes txs are removed from the mempool.
        assert not self.manager.tx_storage.transaction_exists(b11.hash)
        assert not self.manager.tx_storage.transaction_exists(b12.hash)
        assert not self.manager.tx_storage.transaction_exists(b13.hash)
        assert not self.manager.tx_storage.transaction_exists(nc1.hash)
        assert not self.manager.tx_storage.transaction_exists(ocb1.hash)
        assert not self.manager.tx_storage.transaction_exists(fbt.hash)
        assert not self.manager.tx_storage.transaction_exists(fee_tx.hash)
        assert not self.manager.tx_storage.transaction_exists(op_v2_b.hash)
        assert nc1 not in list(self.manager.tx_storage.iter_mempool_tips())
        assert ocb1 not in list(self.manager.tx_storage.iter_mempool_tips())
        assert fbt not in list(self.manager.tx_storage.iter_mempool_tips())
        assert fee_tx not in list(self.manager.tx_storage.iter_mempool_tips())
        assert op_v2_b not in list(self.manager.tx_storage.iter_mempool_tips())

        # The feature states re-activate.
        artifacts.propagate_with(self.manager, up_to='a12')
        assert self.feature_service.get_state(block=a12, feature=Feature.NANO_CONTRACTS) == FeatureState.ACTIVE
        assert self.feature_service.get_state(block=a12, feature=Feature.FEE_TOKENS) == FeatureState.ACTIVE
        assert self.feature_service.get_state(block=a12, feature=Feature.OPCODES_V2) == FeatureState.ACTIVE

        assert b11.get_metadata().nc_block_root_id == self.empty_root_id
        assert b12.get_metadata().nc_block_root_id == self.empty_root_id
        assert b13.get_metadata().nc_block_root_id not in (self.empty_root_id, None)
        assert a11.get_metadata().nc_block_root_id == self.empty_root_id
        assert a12.get_metadata().nc_block_root_id == self.empty_root_id

        # The nc and fee txs are re-accepted on the mempool.
        self._reset_vertex(nc1)
        self.vertex_handler.on_new_relayed_vertex(nc1)
        assert nc1.get_metadata().validation.is_valid()
        assert nc1.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(nc1.hash)
        assert nc1 in list(self.manager.tx_storage.iter_mempool_tips())

        self._reset_vertex(ocb1)
        self.vertex_handler.on_new_relayed_vertex(ocb1)
        assert ocb1.get_metadata().validation.is_valid()
        assert ocb1.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(ocb1.hash)
        assert ocb1 in list(self.manager.tx_storage.iter_mempool_tips())

        self._reset_vertex(fbt)
        self.vertex_handler.on_new_relayed_vertex(fbt)
        assert fbt.get_metadata().validation.is_valid()
        assert fbt.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(fbt.hash)
        assert fbt in list(self.manager.tx_storage.iter_mempool_tips())

        self._reset_vertex(fee_tx)
        self.vertex_handler.on_new_relayed_vertex(fee_tx)
        assert fee_tx.get_metadata().validation.is_valid()
        assert fee_tx.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(fee_tx.hash)
        assert fee_tx in list(self.manager.tx_storage.iter_mempool_tips())

        artifacts.propagate_with(self.manager, up_to='a13')

        assert b11.get_metadata().nc_block_root_id == self.empty_root_id
        assert b12.get_metadata().nc_block_root_id == self.empty_root_id
        assert b13.get_metadata().nc_block_root_id not in (self.empty_root_id, None)
        assert a11.get_metadata().nc_block_root_id == self.empty_root_id
        assert a12.get_metadata().nc_block_root_id == self.empty_root_id
        assert a13.get_metadata().nc_block_root_id not in (self.empty_root_id, None)

    def _reset_vertex(self, vertex: Vertex) -> None:
        assert vertex.storage is not None
        vertex._metadata = None
        for child in vertex.get_children():
            vertex.storage.vertex_children.remove_child(vertex, child)
