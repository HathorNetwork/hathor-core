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

from hathor.daa import DAAFactory, TestMode
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TestBfsRegression(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        feature_settings = FeatureSettings(evaluation_interval=4, default_threshold=4)
        settings = self._settings.model_copy(update={
            'FEATURE_ACTIVATION': feature_settings,
            'REWARD_SPEND_MIN_BLOCKS': 1,  # for simplicity
        })
        daa_factory = DAAFactory(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa_factory(daa_factory)
        self.manager = self.create_peer_from_builder(builder)
        self.tx_storage = self.manager.tx_storage

    def _assert_block_tie(self, x: Block, y: Block) -> None:
        assert x.get_metadata().score == y.get_metadata().score
        if x.hash < y.hash:
            assert not x.get_metadata().voided_by
            assert y.get_metadata().voided_by
        else:
            assert x.get_metadata().voided_by
            assert not y.get_metadata().voided_by

    def test_bfs_regression(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..7]
            blockchain b6 a[7..8]
            b1.out[0] <<< tx1
            b7 < a7 < a8 < tx1
        ''')

        b7, a7, a8 = artifacts.get_typed_vertices(['b7', 'a7', 'a8'], Block)
        tx1, = artifacts.get_typed_vertices(['tx1'], Transaction)

        artifacts.propagate_with(self.manager, up_to='b6')

        # sanity check:
        assert b7.get_metadata().validation.is_initial()
        assert a7.get_metadata().validation.is_initial()
        assert a8.get_metadata().validation.is_initial()
        assert tx1.get_metadata().validation.is_initial()

        # add b7
        artifacts.propagate_with(self.manager, up_to='b7')

        # sanity check:
        assert not b7.get_metadata().validation.is_initial()
        assert not b7.get_metadata().voided_by
        assert a7.get_metadata().validation.is_initial()
        assert a8.get_metadata().validation.is_initial()
        assert tx1.get_metadata().validation.is_initial()

        # add a7 (ties with b7, both are voided)
        artifacts.propagate_with(self.manager, up_to='a7')

        # sanity check:
        assert not b7.get_metadata().validation.is_initial()
        assert not a7.get_metadata().validation.is_initial()
        self._assert_block_tie(a7, b7)
        assert a8.get_metadata().validation.is_initial()
        assert tx1.get_metadata().validation.is_initial()

        # add tx1 before a8, this way tx1 will continue in the mempool after the re-org triggered by a8
        artifacts.propagate_with(self.manager, up_to_before='a8')
        self.manager.vertex_handler.on_new_relayed_vertex(tx1)

        # sanity check:
        assert not b7.get_metadata().validation.is_initial()
        assert not a7.get_metadata().validation.is_initial()
        assert not tx1.get_metadata().validation.is_initial()
        self._assert_block_tie(a7, b7)
        assert not tx1.get_metadata().voided_by
        assert a8.get_metadata().validation.is_initial()

        # since tx1 will be visited and it spends an output from b1, when scanning the mempool for affected
        # transactions, b1 will normally come up, but its neighbors (thus its block-parent) should be ignored, so we
        # get and name b0 in order to verify that it must not be iterated over when the re-org caused by a8 is
        # processed. With evaluation_interval=4, validating a8 may legitimately read b4 for DAA feature activation,
        # but it must not keep walking older block ancestors down to b0.
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

        # add a8, this triggers a re-org such that tx1 is affected and the mempool is scanned for affected txs
        self.manager.vertex_handler.on_new_relayed_vertex(a8)

        # sanity check:
        assert not b7.get_metadata().validation.is_initial()
        assert not a7.get_metadata().validation.is_initial()
        assert not tx1.get_metadata().validation.is_initial()
        assert not a8.get_metadata().validation.is_initial()
        assert b7.get_metadata().voided_by
        assert not a7.get_metadata().voided_by
        assert not tx1.get_metadata().voided_by
        assert not a7.get_metadata().voided_by

        # b0 must not have been read during the processing of a8
        assert b0.hash not in txs_read_from_storage, 'BUG'
