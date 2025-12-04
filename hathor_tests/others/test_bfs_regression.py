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

from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TestBfsRegression(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        settings = self._settings._replace(REWARD_SPEND_MIN_BLOCKS=1)  # for simplicity
        daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)
        self.manager = self.create_peer_from_builder(builder)
        self.tx_storage = self.manager.tx_storage

    def test_bfs_regression(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..3]
            blockchain b2 a[3..4]
            b1.out[0] <<< tx1
            b3 < a3 < a4 < tx1
        ''')

        b3, a3, a4 = artifacts.get_typed_vertices(['b3', 'a3', 'a4'], Block)
        tx1, = artifacts.get_typed_vertices(['tx1'], Transaction)

        artifacts.propagate_with(self.manager, up_to='b2')

        # sanity check:
        assert b3.get_metadata().validation.is_initial()
        assert a3.get_metadata().validation.is_initial()
        assert a4.get_metadata().validation.is_initial()
        assert tx1.get_metadata().validation.is_initial()

        # add b3
        artifacts.propagate_with(self.manager, up_to='b3')

        # sanity check:
        assert not b3.get_metadata().validation.is_initial()
        assert not b3.get_metadata().voided_by
        assert a3.get_metadata().validation.is_initial()
        assert a4.get_metadata().validation.is_initial()
        assert tx1.get_metadata().validation.is_initial()

        # add a3 (ties with b3, both are voided)
        artifacts.propagate_with(self.manager, up_to='a3')

        # sanity check:
        assert not b3.get_metadata().validation.is_initial()
        assert not a3.get_metadata().validation.is_initial()
        assert b3.get_metadata().voided_by
        assert a3.get_metadata().voided_by
        assert a4.get_metadata().validation.is_initial()
        assert tx1.get_metadata().validation.is_initial()

        # add tx1 before a4, this way tx1 will continue in the mempool after the re-org triggered by a4
        artifacts.propagate_with(self.manager, up_to_before='a4')
        self.manager.vertex_handler.on_new_relayed_vertex(tx1)

        # sanity check:
        assert not b3.get_metadata().validation.is_initial()
        assert not a3.get_metadata().validation.is_initial()
        assert not tx1.get_metadata().validation.is_initial()
        assert b3.get_metadata().voided_by
        assert a3.get_metadata().voided_by
        assert not tx1.get_metadata().voided_by
        assert a4.get_metadata().validation.is_initial()

        # since tx1 will be visited and it spends an output from b1, when scanning the mempool for affected
        # transactions, b1 will normally come up, but its neighbors (thus its block-parent) should be ignored, so we
        # get and name b0 in order to verify that it must not be iterated over when the re-org caused by a4 is
        # processed
        b1, = artifacts.get_typed_vertices(['b1',], Block)
        b0 = b1.get_block_parent()
        b0.name = 'b0'

        # inject some code to observe which transactions were read from the storage
        txs_read_from_storage = set()
        orig_get_transaction = self.tx_storage.get_transaction

        def patched_get_transaction(tx_hash):
            txs_read_from_storage.add(tx_hash)
            return orig_get_transaction(tx_hash)
        self.tx_storage.get_transaction = patched_get_transaction  # type: ignore[method-assign]

        # add a4, this triggers a re-org such that tx1 is affected and the mempool is scanned for affected txs
        self.manager.vertex_handler.on_new_relayed_vertex(a4)

        # sanity check:
        assert not b3.get_metadata().validation.is_initial()
        assert not a3.get_metadata().validation.is_initial()
        assert not tx1.get_metadata().validation.is_initial()
        assert not a4.get_metadata().validation.is_initial()
        assert b3.get_metadata().voided_by
        assert not a3.get_metadata().voided_by
        assert not tx1.get_metadata().voided_by
        assert not a3.get_metadata().voided_by

        # b0 must not have been read during the processing of a4
        assert b0.hash not in txs_read_from_storage, 'BUG'
