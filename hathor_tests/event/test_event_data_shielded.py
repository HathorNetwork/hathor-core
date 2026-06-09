# Copyright 2026 Hathor Labs
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

"""Reproducer for incident #242 — Bug A.

`TxData.from_event_arguments` raises pydantic.ValidationError when a tx spends
a shielded output, because `inputs[*].spent_output` is modeled as a transparent
`TxOutput` (requiring `value` / `token_data`) but `get_tx_extra_data` emits the
shielded shape (no `value`) for shielded spent outputs.
"""

from hathor.conf.settings import FeatureSetting
from hathor.dag_builder.builder import DAGArtifacts
from hathor.event.model.event_data import ShieldedTxOutput, TxData, TxOutput
from hathor.pubsub import EventArguments
from hathor.transaction import Block, Transaction
from hathor.transaction.static_metadata import BlockStaticMetadata, TransactionStaticMetadata
from hathor.transaction.validation_state import ValidationState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TxDataShieldedInputTest(unittest.TestCase):
    def setUp(self) -> None:
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

    def _save_all_artifacts(self, artifacts: DAGArtifacts) -> None:
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

    def test_tx_data_from_event_arguments_with_shielded_input(self) -> None:
        """TxData.from_event_arguments must not raise ValidationError on shielded spent outputs."""
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
        event_args = EventArguments(tx=tx2)

        # Before the fix this raises pydantic.ValidationError
        # ("inputs.N.spent_output.value Field required").
        result = TxData.from_event_arguments(event_args)

        shielded = [i for i in result.inputs if isinstance(i.spent_output, ShieldedTxOutput)]
        self.assertEqual(len(shielded), 2)

    def test_tx_data_from_event_arguments_with_mixed_inputs(self) -> None:
        """Same crash also fires when only some inputs are shielded."""
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
        event_args = EventArguments(tx=tx2)

        result = TxData.from_event_arguments(event_args)

        shielded = [i for i in result.inputs if isinstance(i.spent_output, ShieldedTxOutput)]
        transparent = [i for i in result.inputs if isinstance(i.spent_output, TxOutput)]
        self.assertEqual(len(shielded), 1)
        self.assertEqual(len(transparent), 1)


class TxDataShieldedOutputTest(unittest.TestCase):
    """Bug B — ``TxData.from_event_arguments`` silently dropped a tx's
    ``shielded_outputs``.

    ``BaseTransaction.to_json`` emits the shielded outputs under
    ``shielded_outputs`` whenever the tx has any (see
    ``base_transaction.py:806-810``), but ``TxDataWithoutMeta`` had no
    matching field — combined with ``model_config = ConfigDict(extra='ignore')``,
    the key was discarded silently. Wallet-service consumers reading the
    EventQueue WS API never saw shielded outputs of a tx, so wallets in
    wallet-service mode could never discover their shielded receives.
    """
    def setUp(self) -> None:
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

    def _save_all_artifacts(self, artifacts: DAGArtifacts) -> None:
        # Mirror of the helper in TxDataShieldedInputTest. Pulled into both
        # classes deliberately rather than into a shared base to keep the
        # tests self-contained.
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

    def test_tx_data_from_event_arguments_emits_amount_shielded_outputs(self) -> None:
        """AmountShielded outputs land in ``shielded_outputs`` with ``token_data`` set."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR [shielded]
            tx1.out[1] = 50 HTR [shielded]
        """)
        self._save_all_artifacts(artifacts)

        tx1_hash = artifacts.get_typed_vertex('tx1', Transaction).hash
        tx1 = self.manager.tx_storage.get_transaction(tx1_hash)
        event_args = EventArguments(tx=tx1)

        result = TxData.from_event_arguments(event_args)

        # Pre-fix: this list was always empty regardless of the on-chain shape,
        # because pydantic dropped the unknown ``shielded_outputs`` key.
        self.assertEqual(len(result.shielded_outputs), 2)
        for s_out in result.shielded_outputs:
            self.assertEqual(s_out.type, 'shielded')
            # Canonical mode discriminator from OutputMode.AMOUNT_ONLY = 1.
            self.assertEqual(s_out.mode, 1)
            self.assertIsNotNone(s_out.commitment)
            self.assertIsNotNone(s_out.range_proof)
            # AmountShielded discriminator: ``token_data`` is set, the
            # FullShielded-only fields are not.
            self.assertIsNotNone(s_out.token_data)
            self.assertIsNone(s_out.asset_commitment)
            self.assertIsNone(s_out.surjection_proof)

    def test_tx_data_from_event_arguments_emits_full_shielded_outputs(self) -> None:
        """FullShielded outputs land with ``asset_commitment`` and ``surjection_proof``."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 50 HTR [full-shielded]
            tx1.out[1] = 50 HTR [full-shielded]
        """)
        self._save_all_artifacts(artifacts)

        tx1_hash = artifacts.get_typed_vertex('tx1', Transaction).hash
        tx1 = self.manager.tx_storage.get_transaction(tx1_hash)
        event_args = EventArguments(tx=tx1)

        result = TxData.from_event_arguments(event_args)

        self.assertEqual(len(result.shielded_outputs), 2)
        for s_out in result.shielded_outputs:
            self.assertEqual(s_out.type, 'shielded')
            # Canonical mode discriminator from OutputMode.FULLY_SHIELDED = 2.
            self.assertEqual(s_out.mode, 2)
            # FullShielded discriminator: asset_commitment + surjection_proof
            # are present; token_data is absent (token UID is committed under
            # asset_commitment instead of revealed via token_data).
            self.assertIsNotNone(s_out.asset_commitment)
            self.assertIsNotNone(s_out.surjection_proof)
            self.assertIsNone(s_out.token_data)

    def test_tx_data_from_event_arguments_with_mixed_outputs(self) -> None:
        """Mixed transparent + shielded outputs land in their respective fields."""
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            tx1.out[0] = 30 HTR
            tx1.out[1] = 35 HTR [shielded]
            tx1.out[2] = 35 HTR [full-shielded]
        """)
        self._save_all_artifacts(artifacts)

        tx1_hash = artifacts.get_typed_vertex('tx1', Transaction).hash
        tx1 = self.manager.tx_storage.get_transaction(tx1_hash)
        event_args = EventArguments(tx=tx1)

        result = TxData.from_event_arguments(event_args)

        # Transparent outputs stay in ``outputs``; shielded ones move to
        # ``shielded_outputs`` (tx-level fee headers may add additional
        # transparent outputs, so we assert presence rather than exact
        # count for the transparent side).
        transparent_values = [o.value for o in result.outputs]
        self.assertIn(30, transparent_values)

        self.assertEqual(len(result.shielded_outputs), 2)
        # One AmountShielded + one FullShielded per the DSL — partition by
        # the canonical ``mode`` discriminator (1 = AmountShielded,
        # 2 = FullShielded).
        as_outputs = [o for o in result.shielded_outputs if o.mode == 1]
        fs_outputs = [o for o in result.shielded_outputs if o.mode == 2]
        self.assertEqual(len(as_outputs), 1)
        self.assertEqual(len(fs_outputs), 1)
        # And the secondary discriminators stay consistent with ``mode``.
        self.assertIsNotNone(as_outputs[0].token_data)
        self.assertIsNone(as_outputs[0].asset_commitment)
        self.assertIsNotNone(fs_outputs[0].asset_commitment)
        self.assertIsNotNone(fs_outputs[0].surjection_proof)
        self.assertIsNone(fs_outputs[0].token_data)
