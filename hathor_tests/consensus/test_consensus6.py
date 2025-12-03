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
from hathor.graphviz import GraphvizVisualizer
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder

DEBUG: bool = False


class TestConsensus6(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        settings = self._settings._replace(REWARD_SPEND_MIN_BLOCKS=1)  # for simplicity
        daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)

        self.manager = self.create_peer_from_builder(builder)
        self.tx_storage = self.manager.tx_storage

    def test_conflict_on_reorg(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..2]
            blockchain b1 a[2..4]
            b1 < dummy

            b1 < tx1 < tx2 < tx3 < b2
            tx3 <-- b2

            # tx2 has a conflict with tx3
            tx1.out[0] <<< tx2
            tx1.out[0] <<< tx3

            # a2 will generate a reorg
            a2.weight = 10
            b2 < a2
            tx2 <-- a3
        ''')

        b1, b2, a2, a3 = artifacts.get_typed_vertices(['b1', 'b2', 'a2', 'a3'], Block)
        tx1, tx2, tx3, dummy = artifacts.get_typed_vertices(['tx1', 'tx2', 'tx3', 'dummy'], Transaction)

        artifacts.propagate_with(self.manager, up_to='b1')

        assert b1.get_metadata().voided_by is None

        assert tx1.get_metadata().validation.is_initial()
        assert tx2.get_metadata().validation.is_initial()
        assert tx3.get_metadata().validation.is_initial()

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by is None
        assert tx3.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block is None

        assert tx1.get_metadata().accumulated_weight == 2
        assert tx2.get_metadata().accumulated_weight == 2
        assert tx3.get_metadata().accumulated_weight == 2

        artifacts.propagate_with(self.manager, up_to='tx3')

        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('before-b2')

        artifacts.propagate_with(self.manager, up_to='b2')

        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-b2')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by is None

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block == b2.hash
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block == b2.hash

        assert tx1.get_metadata().accumulated_weight == 2
        assert tx2.get_metadata().accumulated_weight == 2
        assert tx3.get_metadata().accumulated_weight == 4

        artifacts.propagate_with(self.manager, up_to='a2')

        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-a2')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by == {b2.hash}
        assert a2.get_metadata().voided_by is None

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block is None

        assert tx1.get_metadata().accumulated_weight == 2
        assert tx2.get_metadata().accumulated_weight == 2
        assert tx3.get_metadata().accumulated_weight == 4

        artifacts.propagate_with(self.manager, up_to='a3')

        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-a3')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by == {b2.hash, tx3.hash}
        assert a2.get_metadata().voided_by is None
        assert a3.get_metadata().voided_by == {a3.hash, tx2.hash}

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by == {tx3.hash}

        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block is None

        assert tx1.get_metadata().accumulated_weight == 2
        assert tx2.get_metadata().accumulated_weight == 4
        assert tx3.get_metadata().accumulated_weight == 4

        artifacts.propagate_with(self.manager, up_to='a4')

        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-a4')
