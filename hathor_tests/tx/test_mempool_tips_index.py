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


class TestMempoolTipsIndex(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        settings = self._settings._replace(REWARD_SPEND_MIN_BLOCKS=1)  # for simplicity
        daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)

        self.manager = self.create_peer_from_builder(builder)
        self.tx_storage = self.manager.tx_storage
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.mempool_tips is not None
        self.mempool_tips = self.tx_storage.indexes.mempool_tips

        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_mempool_tip_spender_became_valid(self) -> None:
        """
        Covers the case where a tx spending a tip becomes non-voided, making the tip not a tip anymore.
        It's a long test that probably also covers more stuff, as it was created during a debug session.
        """
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..3]
            blockchain b1 a[2..4]
            b1 < dummy

            b1 < tx1 < tx2 < tx3 < tx4 < b2
            tx3 <-- b2
            tx4 <-- b3

            # tx2 has a conflict with tx4
            tx1.out[0] <<< tx2
            tx1.out[0] <<< tx4

            # a2 will generate a reorg
            a2.weight = 10
            b3 < a2
            tx2 <-- a3
        ''')

        b1, b2, b3, a2, a3, a4 = artifacts.get_typed_vertices(['b1', 'b2', 'b3', 'a2', 'a3', 'a4'], Block)
        tx1, tx2, tx3, tx4, dummy = artifacts.get_typed_vertices(
            ['tx1', 'tx2', 'tx3', 'tx4', 'dummy'],
            Transaction,
        )

        artifacts.propagate_with(self.manager, up_to='b1')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-b1')

        assert b1.get_metadata().voided_by is None

        assert tx1.get_metadata().validation.is_initial()
        assert tx2.get_metadata().validation.is_initial()
        assert tx3.get_metadata().validation.is_initial()
        assert tx4.get_metadata().validation.is_initial()

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by is None
        assert tx3.get_metadata().voided_by is None
        assert tx4.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block is None
        assert tx4.get_metadata().first_block is None

        assert set(self.mempool_tips.iter(self.tx_storage)) == set()
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == set()

        artifacts.propagate_with(self.manager, up_to='tx4')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-tx4')

        assert set(self.mempool_tips.iter(self.tx_storage)) == {tx1, tx3}
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == {tx1, tx3, dummy}

        artifacts.propagate_with(self.manager, up_to='b2')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-b2')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by is None

        assert tx1.get_metadata().validation.is_valid()
        assert tx2.get_metadata().validation.is_valid()
        assert tx3.get_metadata().validation.is_valid()
        assert tx4.get_metadata().validation.is_valid()

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by is None
        assert tx4.get_metadata().voided_by == {tx4.hash}

        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block == b2.hash
        assert tx4.get_metadata().first_block is None

        assert set(self.mempool_tips.iter(self.tx_storage)) == {tx1}
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == {tx1}

        artifacts.propagate_with(self.manager, up_to='b3')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-b3')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by is None
        assert b3.get_metadata().voided_by is None

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by is None
        assert tx4.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block == b3.hash
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block == b2.hash
        assert tx4.get_metadata().first_block == b3.hash

        assert set(self.mempool_tips.iter(self.tx_storage)) == set()
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == set()

        artifacts.propagate_with(self.manager, up_to='a2')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-a2')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by == {b2.hash}
        assert b3.get_metadata().voided_by == {b3.hash}
        assert a2.get_metadata().voided_by is None

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by is None
        assert tx4.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block is None
        assert tx4.get_metadata().first_block is None

        assert set(self.mempool_tips.iter(self.tx_storage)) == {tx3, tx4}
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == {dummy, tx1, tx3, tx4}

        artifacts.propagate_with(self.manager, up_to='a3')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-a3')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by == {b2.hash}
        assert b3.get_metadata().voided_by == {b3.hash, tx4.hash}
        assert a2.get_metadata().voided_by is None
        assert a3.get_metadata().voided_by == {a3.hash, tx2.hash}

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by is None
        assert tx4.get_metadata().voided_by == {tx4.hash}

        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx3.get_metadata().first_block is None
        assert tx4.get_metadata().first_block is None

        assert set(self.mempool_tips.iter(self.tx_storage)) == {tx1, tx3}
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == {dummy, tx1, tx3}

        artifacts.propagate_with(self.manager, up_to='a4')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-a4')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by == {b2.hash}
        assert b3.get_metadata().voided_by == {b3.hash, tx4.hash}
        assert a2.get_metadata().voided_by is None
        assert a3.get_metadata().voided_by is None
        assert a4.get_metadata().voided_by is None

        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by is None
        assert tx3.get_metadata().voided_by is None
        assert tx4.get_metadata().voided_by == {tx4.hash}

        assert tx1.get_metadata().first_block == a3.hash
        assert tx2.get_metadata().first_block == a3.hash
        assert tx3.get_metadata().first_block is None
        assert tx4.get_metadata().first_block is None

        assert set(self.mempool_tips.iter(self.tx_storage)) == {tx3}
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == {tx3}

    def test_mempool_tip_became_voided_with_spent(self) -> None:
        """Covers the case where a tip becomes voided, making the tx it was spending a new tip."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..2]
            b1 < dummy < tx1 < tx2 < b2

            tx_spent.out[0] <<< tx1
            tx0.out[0] <<< tx1
            tx0.out[0] <<< tx2

            tx1.weight = 10

            b2.weight = 10
            tx2 <-- b2
        ''')

        b1, b2 = artifacts.get_typed_vertices(['b1', 'b2'], Block)
        dummy, tx0, tx1, tx2, tx_spent = artifacts.get_typed_vertices(
            ['dummy', 'tx0', 'tx1', 'tx2', 'tx_spent'],
            Transaction,
        )

        artifacts.propagate_with(self.manager, up_to='tx2')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-tx2')

        assert b1.get_metadata().voided_by is None

        assert tx0.get_metadata().voided_by is None
        assert tx1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx_spent.get_metadata().voided_by is None

        assert tx0.get_metadata().first_block is None
        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block is None
        assert tx_spent.get_metadata().first_block is None

        assert set(self.mempool_tips.iter(self.tx_storage)) == {tx1}
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == {dummy, tx_spent, tx0, tx1}

        artifacts.propagate_with(self.manager, up_to='b2')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-b2')

        assert b1.get_metadata().voided_by is None
        assert b2.get_metadata().voided_by is None

        assert tx0.get_metadata().voided_by is None
        assert tx1.get_metadata().voided_by == {tx1.hash}
        assert tx2.get_metadata().voided_by is None
        assert tx_spent.get_metadata().voided_by is None

        assert tx0.get_metadata().first_block == b2.hash
        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block == b2.hash
        assert tx_spent.get_metadata().first_block is None

        assert set(self.mempool_tips.iter(self.tx_storage)) == {tx_spent}
        assert set(self.mempool_tips.iter_all(self.tx_storage)) == {tx_spent}

    def test_mempool_tips_on_voided_block(self) -> None:
        """Test that the mempool tips index is updated when a block is voided."""
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            blockchain b10 a[11..11]
            b10 < dummy

            tx1 <-- b11

            # a11 makes b11 be voided
            a11.weight = 10
            b11 < a11

            # b12 makes a11 be voided
            b12.weight = 10
            a11 < b12
        ''')

        tx1, = artifacts.get_typed_vertices(['tx1'], Transaction)
        b11, a11, b12 = artifacts.get_typed_vertices(['b11', 'a11', 'b12'], Block)

        # Propagate up to tx1, it should be added to the mempool tips index.
        artifacts.propagate_with(self.manager, up_to='tx1')

        assert tx1.get_metadata().first_block is None
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None

        assert tx1 in self.mempool_tips.iter_all(self.tx_storage)
        assert tx1 in self.mempool_tips.iter(self.tx_storage)

        # Propagate up to b11, tx1 will be confirmed by it,
        # and therefore it should be removed from the mempool tips index.
        artifacts.propagate_with(self.manager, up_to='b11')

        assert b11.get_metadata().validation.is_valid()
        assert b11.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None

        assert tx1 not in self.mempool_tips.iter_all(self.tx_storage)
        assert tx1 not in self.mempool_tips.iter(self.tx_storage)

        # Propagate up to a11, b11 will be voided, and therefore tx1 should be readded to the mempool tips index.
        artifacts.propagate_with(self.manager, up_to='a11')

        assert b11.get_metadata().validation.is_valid()
        assert b11.get_metadata().voided_by == {b11.hash}

        assert a11.get_metadata().validation.is_valid()
        assert a11.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block is None
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None

        assert tx1 in self.mempool_tips.iter_all(self.tx_storage)
        assert tx1 in self.mempool_tips.iter(self.tx_storage)

        # Propagate up to b12, a11 will be voided,
        # and therefore tx1 should be removed from the mempool tips index again.
        artifacts.propagate_with(self.manager, up_to='b12')

        assert b11.get_metadata().validation.is_valid()
        assert b11.get_metadata().voided_by is None

        assert a11.get_metadata().validation.is_valid()
        assert a11.get_metadata().voided_by == {a11.hash}

        assert b12.get_metadata().validation.is_valid()
        assert b12.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None

        assert tx1 not in self.mempool_tips.iter_all(self.tx_storage)
        assert tx1 not in self.mempool_tips.iter(self.tx_storage)
