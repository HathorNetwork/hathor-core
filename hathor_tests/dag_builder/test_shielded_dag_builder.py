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

"""Tests for DAG Builder shielded output support."""

from hathor.conf.settings import FeatureSetting
from hathor.transaction import Transaction
from hathor.transaction.headers import ShieldedOutputsHeader
from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class ShieldedDAGBuilderTestCase(unittest.TestCase):
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

    def test_amount_only_shielded_output(self) -> None:
        """DSL: tx1.out[0] = 100 HTR [shielded] creates AmountShieldedOutput."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR [shielded]
            tx1.out[1] = 50 HTR [shielded]
        """)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        self.assertTrue(tx1.has_shielded_outputs())
        shielded = tx1.shielded_outputs
        self.assertEqual(len(shielded), 2)
        for output in shielded:
            self.assertIsInstance(output, AmountShieldedOutput)
            self.assertEqual(len(output.commitment), 33)
            self.assertGreater(len(output.range_proof), 0)
            self.assertGreater(len(output.script), 0)
            self.assertEqual(output.token_data, 0)  # HTR

    def test_fully_shielded_output(self) -> None:
        """DSL: tx1.out[0] = 100 HTR [full-shielded] creates FullShieldedOutput."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR [full-shielded]
            tx1.out[1] = 50 HTR [full-shielded]
        """)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        self.assertTrue(tx1.has_shielded_outputs())
        shielded = tx1.shielded_outputs
        self.assertEqual(len(shielded), 2)
        for output in shielded:
            self.assertIsInstance(output, FullShieldedOutput)
            self.assertEqual(len(output.commitment), 33)
            self.assertGreater(len(output.range_proof), 0)
            self.assertGreater(len(output.script), 0)
            self.assertEqual(len(output.asset_commitment), 33)
            self.assertGreater(len(output.surjection_proof), 0)

    def test_mixed_transparent_and_shielded(self) -> None:
        """Transparent and shielded outputs on the same transaction."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR
            tx1.out[1] = 25 HTR [shielded]
            tx1.out[2] = 25 HTR [shielded]
        """)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        # Transparent outputs
        self.assertGreaterEqual(len(tx1.outputs), 1)
        # Shielded outputs
        self.assertTrue(tx1.has_shielded_outputs())
        shielded = tx1.shielded_outputs
        self.assertEqual(len(shielded), 2)
        for output in shielded:
            self.assertIsInstance(output, AmountShieldedOutput)

    def test_header_serialization_roundtrip(self) -> None:
        """ShieldedOutputsHeader can be serialized and deserialized."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR [shielded]
            tx1.out[1] = 50 HTR [shielded]
        """)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        header = tx1.get_shielded_outputs_header()

        # Serialize
        data = header.serialize()
        self.assertIsInstance(data, bytes)
        self.assertGreater(len(data), 0)

        # Deserialize
        restored, remaining = ShieldedOutputsHeader.deserialize(tx1, data)
        self.assertEqual(len(remaining), 0)
        self.assertEqual(len(restored.shielded_outputs), len(header.shielded_outputs))

        for orig, rest in zip(header.shielded_outputs, restored.shielded_outputs):
            self.assertEqual(orig.commitment, rest.commitment)
            self.assertEqual(orig.range_proof, rest.range_proof)
            self.assertEqual(orig.script, rest.script)

    def test_mixed_shielded_types(self) -> None:
        """Both AmountShielded and FullShielded on the same transaction."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR [shielded]
            tx1.out[1] = 50 HTR [full-shielded]
        """)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        shielded = tx1.shielded_outputs
        self.assertEqual(len(shielded), 2)
        types = {type(o) for o in shielded}
        self.assertEqual(types, {AmountShieldedOutput, FullShieldedOutput})
