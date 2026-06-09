# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression tests for get_tx_extra_data with shielded outputs."""

from hathor.conf.settings import FeatureSetting
from hathor.transaction import Block, Transaction
from hathor.transaction.resources.transaction import get_tx_extra_data
from hathor.transaction.static_metadata import BlockStaticMetadata, TransactionStaticMetadata
from hathor.transaction.validation_state import ValidationState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class GetTxExtraDataShieldedTest(unittest.TestCase):
    def setUp(self):
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        settings = self._settings.model_copy(update={
            'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED,
        })

        builder = self.get_builder(settings) \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)

        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _save_all_artifacts(self, artifacts):
        """Save all DAG builder vertices to storage, bypassing full validation."""
        storage = self.manager.tx_storage
        genesis_hashes = {g.hash for g in storage.get_all_genesis()}
        height = 0
        for _node, vertex in artifacts.list:
            if vertex.hash in genesis_hashes:
                continue
            vertex.storage = storage
            vertex.set_validation(ValidationState.FULL)
            if isinstance(vertex, Block):
                height += 1
                vertex.set_static_metadata(
                    BlockStaticMetadata(
                        min_height=0,
                        height=height,
                        feature_activation_bit_counts=[],
                        feature_states={},
                    )
                )
            else:
                vertex.set_static_metadata(
                    TransactionStaticMetadata(min_height=0, closest_ancestor_block=b'')
                )
            with storage.allow_partially_validated_context():
                storage.save_transaction(vertex)

    def test_get_tx_extra_data_spending_shielded_output(self) -> None:
        """get_tx_extra_data must not crash when a tx input spends a shielded output.

        Before the fix, tx2.outputs[tx_in.index] raised IndexError because the
        index refers to a shielded output in the combined index space, not the
        transparent outputs list.
        """
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR [shielded]
            tx1.out[1] = 50 HTR [shielded]

            tx1.out[0] <<< tx2
            tx1.out[1] <<< tx2
            tx2.out[0] = 50 HTR [shielded]
            tx2.out[1] = 50 HTR [shielded]
        """)
        self._save_all_artifacts(artifacts)

        tx2_hash = artifacts.get_typed_vertex('tx2', Transaction).hash
        tx2 = self.manager.tx_storage.get_transaction(tx2_hash)

        # This used to raise IndexError
        result = get_tx_extra_data(tx2, detail_tokens=False)
        self.assertTrue(result['success'])

        # The shielded input should be serialized with type='shielded'
        inputs = result['tx']['inputs']
        self.assertGreater(len(inputs), 0)
        shielded_inputs = [i for i in inputs if i.get('type') == 'shielded']
        self.assertGreater(len(shielded_inputs), 0)
        # And carry the canonical ``mode`` discriminator from
        # ``OutputMode`` (1 = AmountShielded, 2 = FullShielded). The
        # DSL above produces AmountShielded outputs (``[shielded]``).
        for s_in in shielded_inputs:
            self.assertEqual(s_in['mode'], 1)

        # The tx's own shielded outputs are serialized at the top level
        # under ``shielded_outputs``; assert the ``mode`` field is there
        # too so the normal REST API path matches the events API path.
        shielded_outputs = result['tx'].get('shielded_outputs', [])
        self.assertEqual(len(shielded_outputs), 2)
        for s_out in shielded_outputs:
            self.assertEqual(s_out['type'], 'shielded')
            self.assertEqual(s_out['mode'], 1)

    def test_get_tx_extra_data_mixed_inputs(self) -> None:
        """get_tx_extra_data handles a tx with both transparent and shielded inputs."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR
            tx1.out[1] = 25 HTR [shielded]
            tx1.out[2] = 25 HTR [shielded]

            tx1.out[0] <<< tx2
            tx1.out[1] <<< tx2
            tx2.out[0] = 25 HTR [shielded]
            tx2.out[1] = 25 HTR [shielded]
        """)
        self._save_all_artifacts(artifacts)

        tx2_hash = artifacts.get_typed_vertex('tx2', Transaction).hash
        tx2 = self.manager.tx_storage.get_transaction(tx2_hash)

        result = get_tx_extra_data(tx2, detail_tokens=False)
        self.assertTrue(result['success'])

        inputs = result['tx']['inputs']
        shielded_inputs = [i for i in inputs if i.get('type') == 'shielded']
        transparent_inputs = [i for i in inputs if i.get('type') != 'shielded']
        self.assertGreater(len(shielded_inputs), 0)
        self.assertGreater(len(transparent_inputs), 0)
