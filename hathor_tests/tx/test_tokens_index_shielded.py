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

"""Reproducer for incident #242 — Bug B.

`RocksDBTokensIndex._remove_utxo` does `tx_output = tx.outputs[index]`, which
assumes the spent output index always points into the transparent outputs list.
That assumption is invalid for shielded outputs, where the combined output
index space includes entries not present in `tx.outputs`, raising
`IndexError: list index out of range` from `add_to_non_critical_indexes`.
"""

from hathor.conf.settings import FeatureSetting
from hathor.transaction import Block, Transaction
from hathor.transaction.static_metadata import BlockStaticMetadata, TransactionStaticMetadata
from hathor.transaction.validation_state import ValidationState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TokensIndexShieldedSpentOutputTest(unittest.TestCase):
    def setUp(self):
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        settings = self._settings.model_copy(update={
            'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED,
        })

        builder = self.get_builder(settings) \
            .enable_tokens_index() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)

        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _save_all_artifacts(self, artifacts):
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

    def test_tokens_index_add_tx_with_shielded_spent_output(self) -> None:
        """tokens.add_tx must skip shielded inputs instead of crashing.

        Before the fix: `_remove_utxo(spent_tx, tx_input.index)` does
        `spent_tx.outputs[tx_input.index]` and the index points past the
        transparent outputs list, raising IndexError.
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

        tokens_index = self.manager.tx_storage.indexes.tokens
        assert tokens_index is not None

        # Used to raise: IndexError: list index out of range (rocksdb_tokens_index.py:382)
        tokens_index.add_tx(tx2)

    def test_tokens_index_add_tx_with_mixed_inputs(self) -> None:
        """Same fix path: tx with one transparent + one shielded input."""
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

        tokens_index = self.manager.tx_storage.indexes.tokens
        assert tokens_index is not None

        tokens_index.add_tx(tx2)
