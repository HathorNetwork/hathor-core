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

from hathor.conf.settings import FeatureSetting
from hathor.transaction import Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput, OutputMode


class DAGBuilderShieldedTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        settings = self._settings.model_copy(
            update={'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED}
        )
        builder = self.get_builder() \
            .set_settings(settings) \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)

        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_shielded_outputs_attached_and_accepted(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b1.out[0] <<< tx1
            b30 < tx1      # reward lock for tx1 spending b1's reward
            b30 < dummy    # reward lock for the auto-created funding tx (spends genesis)

            tx1.out[0] = 100 HTR [wallet1]
            tx1.sout[0] = 30 HTR [wallet2]
            tx1.sout[1] = 20 HTR [wallet3] [full-shielded]
        """)
        artifacts.propagate_with(self.manager)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)

        # header attached, correct count and modes
        assert tx1.has_shielded_outputs()
        souts = tx1.shielded_outputs
        assert len(souts) == 2
        assert isinstance(souts[0], AmountShieldedOutput)
        assert souts[0].mode() == OutputMode.AMOUNT_ONLY
        assert isinstance(souts[1], FullShieldedOutput)
        assert souts[1].mode() == OutputMode.FULLY_SHIELDED

        # accepted by the node (not voided)
        meta = tx1.get_metadata()
        assert not meta.voided_by

        # round-trips through storage serialization
        loaded = self.manager.tx_storage.get_transaction(tx1.hash)
        assert isinstance(loaded, Transaction)
        assert loaded.has_shielded_outputs()
        assert len(loaded.shielded_outputs) == 2

    def test_shielded_output_with_custom_token(self) -> None:
        # Exercises the custom-token branch (token_data != 0), where token_uid
        # must be resolved from the token id rather than the HTR uid.
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b1.out[0] <<< tx1
            b30 < tx1
            b30 < dummy

            tx1.out[0] = 100 HTR [wallet1]
            tx1.out[1] = 50 TKA [wallet1]
            tx1.sout[0] = 30 TKA [wallet2]
        """)
        artifacts.propagate_with(self.manager)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        assert tx1.has_shielded_outputs()
        souts = tx1.shielded_outputs
        assert len(souts) == 1
        assert isinstance(souts[0], AmountShieldedOutput)
        # custom token -> token_data is a 1-based index into tx.tokens (not 0/HTR)
        assert souts[0].token_data != 0
        assert not tx1.get_metadata().voided_by
