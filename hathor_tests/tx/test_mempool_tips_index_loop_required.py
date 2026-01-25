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

"""
Tests that demonstrate why the O(n) loop in MempoolTipsIndex.update() is required.

The O(n) loop in update() (lines 139-154 in mempool_tips_index.py) iterates over
ALL current tips to check:
1. If any tip became voided (due to a reorg or double-spend resolution)
2. If any tip now has a valid child or spender (which disqualifies it as a tip)

TEST SUMMARY (behavior WITHOUT the O(n) loop):

1. test_tip_has_spender_confirmed_directly:
   - Scenario: A tip's spender is directly confirmed by a block
   - Without O(n) loop: PASSES (handled by _discard_many(tx.get_all_dependencies()))
   - The spender is the transaction being processed, so its dependencies are discarded

2. test_tip_has_spender_unvoided_via_double_spend:
   - Scenario: A tip's voided spender becomes valid when block confirms the spender
   - Without O(n) loop: PASSES (handled by _discard_many(tx.get_all_dependencies()))
   - Same as above - the spender is directly processed

3. test_tip_becomes_voided_via_double_spend_confirmation:
   - Scenario: A tip becomes voided when block confirms its double-spend competitor
   - Without O(n) loop: FAILS - requires O(n) loop
   - The tip is NOT the transaction being processed; it's voided as a side effect

KEY INSIGHT:
The O(n) loop is needed for INDIRECT consensus changes. When a tip's status changes
as a SIDE EFFECT (not as the directly processed transaction), only the O(n) loop
can detect this. The _discard_many(tx.get_all_dependencies()) code path only
handles the direct case where the processed transaction's dependencies are affected.
"""

from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.graphviz import GraphvizVisualizer
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder

DEBUG: bool = False


class TestMempoolTipsIndexLoopRequired(unittest.TestCase):
    """
    Tests that would fail if the O(n) loop in update() were removed.

    The O(n) loop is needed because consensus changes can have cascading effects
    on tips that are not directly related to the transaction being processed.
    """

    def setUp(self) -> None:
        super().setUp()
        settings = self._settings._replace(REWARD_SPEND_MIN_BLOCKS=1)
        daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa)

        self.manager = self.create_peer_from_builder(builder)
        self.tx_storage = self.manager.tx_storage
        self.mempool_tips = self.tx_storage.indexes.mempool_tips

        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_tip_has_spender_confirmed_directly(self) -> None:
        """
        Test case: A tip's spender is confirmed by a block. The tip should be
        removed from the index.

        NOTE: This test demonstrates the INTENDED behavior but passes even
        without the O(n) loop because of the _discard_many(tx.get_all_dependencies())
        code path. When tx_spender is confirmed by the block, update() is called
        with tx_spender, and tx_parent is in tx_spender.get_all_dependencies().

        The O(n) loop is specifically needed for INDIRECT cases where the spender
        becomes valid as a side effect (not as the transaction being processed).
        See test_tip_becomes_voided_via_double_spend_confirmation for a case that
        actually requires the O(n) loop.
        """
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..3]
            b1 < dummy

            # tx_parent will be a tip initially
            b1 < tx_parent

            # tx_spender spends tx_parent
            tx_parent < tx_spender
            tx_parent.out[0] <<< tx_spender

            # b3 confirms tx_spender
            tx_spender <-- b3
        ''')

        b1, b3 = artifacts.get_typed_vertices(['b1', 'b3'], Block)
        tx_parent, tx_spender = artifacts.get_typed_vertices(
            ['tx_parent', 'tx_spender'],
            Transaction,
        )

        # First propagate the blockchain to unlock rewards
        artifacts.propagate_with(self.manager, up_to='b1')

        # Propagate transactions (before the confirming block)
        artifacts.propagate_with(self.manager, up_to='tx_spender')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('test_direct_before_block')

        # Verify initial state: both tx_parent and tx_spender are tips
        assert tx_parent.get_metadata().voided_by is None, "tx_parent should be valid"
        assert tx_spender.get_metadata().voided_by is None, "tx_spender should be valid"
        tips = set(self.mempool_tips.iter(self.tx_storage))
        # tx_parent is NOT a tip because tx_spender (valid) spends it
        assert tx_parent not in tips, "tx_parent should not be a tip (tx_spender spends it)"
        assert tx_spender in tips, "tx_spender should be a tip"

        # Now propagate b3, which confirms tx_spender
        artifacts.propagate_with(self.manager, up_to='b3')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('test_direct_after_block')

        # Verify: tx_spender is confirmed, tx_parent is still not a tip
        assert tx_spender.get_metadata().first_block == b3.hash
        tips = set(self.mempool_tips.iter(self.tx_storage))
        assert tx_parent not in tips, "tx_parent should not be a tip"
        assert tx_spender not in tips, "tx_spender should not be a tip (confirmed)"

    def test_tip_has_spender_unvoided_via_double_spend(self) -> None:
        """
        Test case: A tip's spender was voided (lost a double-spend) but becomes
        valid when a block confirms it. The tip should be removed from the index.

        Scenario:
        - tx_parent is a tip (valid, in mempool)
        - tx_spender spends tx_parent AND tx_source (double-spending with tx_winner)
        - tx_winner wins initially (higher weight), so tx_spender is voided
        - tx_parent remains a tip because its only spender is voided
        - A block confirms tx_spender
        - tx_spender becomes valid, tx_winner becomes voided
        - tx_parent should NOT be a tip anymore

        Without the O(n) loop: PASSES
        This case is handled by _discard_many(tx.get_all_dependencies()) because
        tx_spender is the transaction being directly processed (confirmed by block),
        and tx_parent is in tx_spender.get_all_dependencies().
        """
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..3]
            b1 < dummy

            # tx_parent will be a tip - it has no valid spenders initially
            b1 < tx_parent

            # tx_source provides an output that tx_spender and tx_winner will fight over
            b1 < tx_source

            # tx_winner arrives FIRST (spends only tx_source)
            # tx_winner has higher weight so it wins the double-spend
            tx_source.out[0] <<< tx_winner
            tx_winner.weight = 10

            # tx_spender depends on tx_winner (to ensure proper ordering)
            # and spends both tx_parent and tx_source (conflicting with tx_winner on tx_source)
            tx_winner < tx_spender
            tx_parent.out[0] <<< tx_spender
            tx_source.out[0] <<< tx_spender

            # b3 confirms tx_spender, making tx_winner voided and tx_spender valid
            tx_spender <-- b3
            b3.weight = 10
        ''')

        b1, b3 = artifacts.get_typed_vertices(['b1', 'b3'], Block)
        tx_parent, tx_source, tx_spender, tx_winner = artifacts.get_typed_vertices(
            ['tx_parent', 'tx_source', 'tx_spender', 'tx_winner'],
            Transaction,
        )

        # First propagate the blockchain to unlock rewards
        artifacts.propagate_with(self.manager, up_to='b1')

        # Now propagate transactions up to tx_spender (before the confirming block)
        artifacts.propagate_with(self.manager, up_to='tx_spender')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('test_spender_unvoided_before_block')

        # Verify initial state:
        # - tx_parent is valid and in mempool
        # - tx_spender is voided (lost double-spend to tx_winner)
        # - tx_winner is valid
        assert tx_parent.get_metadata().voided_by is None, "tx_parent should be valid"
        assert tx_parent.get_metadata().first_block is None, "tx_parent should be in mempool"
        assert tx_spender.get_metadata().voided_by == {tx_spender.hash}, "tx_spender should be voided"
        assert tx_winner.get_metadata().voided_by is None, "tx_winner should be valid"

        # tx_parent should be a tip because its only spender (tx_spender) is voided
        tips = set(self.mempool_tips.iter(self.tx_storage))
        assert tx_parent in tips, (
            "tx_parent should be a tip because tx_spender (its only spender) is voided"
        )
        # tx_winner should also be a tip
        assert tx_winner in tips, "tx_winner should be a tip"

        # Now propagate b3, which confirms tx_spender
        # This should make tx_spender valid and tx_winner voided
        artifacts.propagate_with(self.manager, up_to='b3')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('test_spender_unvoided_after_block')

        # Verify state after b3:
        # - tx_spender is now valid (confirmed by b3)
        # - tx_winner is now voided (lost to tx_spender)
        assert tx_spender.get_metadata().voided_by is None, "tx_spender should be valid now"
        assert tx_spender.get_metadata().first_block == b3.hash, "tx_spender should be confirmed by b3"
        assert tx_winner.get_metadata().voided_by == {tx_winner.hash}, "tx_winner should be voided now"

        # tx_parent should NOT be a tip anymore because tx_spender (which spends tx_parent) is now valid
        #
        # NOTE: This assertion passes even without the O(n) loop because:
        # - The block confirms tx_spender directly
        # - update() is called with tx_spender
        # - _discard_many(tx_spender.get_all_dependencies()) removes tx_parent from tips
        tips = set(self.mempool_tips.iter(self.tx_storage))
        assert tx_parent not in tips, (
            "tx_parent should NOT be a tip anymore because tx_spender (which spends tx_parent) is now valid."
        )

    def test_tip_becomes_voided_via_double_spend_confirmation(self) -> None:
        """
        Test case: A tip becomes voided because a block confirms the competing
        double-spend transaction.

        Scenario:
        - tx_tip is a valid tip (won a double-spend with tx_competitor)
        - tx_competitor is voided
        - A block confirms tx_competitor
        - tx_tip becomes voided
        - tx_tip should be removed from tips

        Without the O(n) loop:
        - When update() is called, tx_tip's voided status changed
        - But tx_tip may not be directly checked if it's not in the transaction graph
          being processed
        """
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..3]
            b1 < dummy

            # tx_tip arrives first and wins initially due to higher weight
            # b2 unlocks b1's reward
            b2 < tx_tip
            b1.out[0] <<< tx_tip
            tx_tip.weight = 10

            # tx_competitor arrives second (double-spend with tx_tip)
            # It is voided because tx_tip has higher weight
            tx_tip < tx_competitor
            b1.out[0] <<< tx_competitor

            # b3 confirms tx_competitor, making tx_tip voided
            tx_competitor <-- b3
            b3.weight = 10
        ''')

        b1, b3 = artifacts.get_typed_vertices(['b1', 'b3'], Block)
        tx_tip, tx_competitor = artifacts.get_typed_vertices(['tx_tip', 'tx_competitor'], Transaction)

        # First propagate the blockchain to unlock rewards
        artifacts.propagate_with(self.manager, up_to='b1')

        # Propagate up to tx_competitor (before the confirming block)
        artifacts.propagate_with(self.manager, up_to='tx_competitor')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('test_voided_before_block')

        # Verify initial state:
        # - tx_tip is valid (won double-spend due to higher weight)
        # - tx_competitor is voided
        assert tx_tip.get_metadata().voided_by is None, "tx_tip should be valid"
        assert tx_competitor.get_metadata().voided_by == {tx_competitor.hash}, "tx_competitor should be voided"

        # tx_tip should be a tip
        tips = set(self.mempool_tips.iter(self.tx_storage))
        assert tx_tip in tips, "tx_tip should be a tip"
        assert tx_competitor not in tips, "tx_competitor should NOT be a tip (voided)"

        # Now propagate b3, which confirms tx_competitor
        # This should make tx_tip voided
        artifacts.propagate_with(self.manager, up_to='b3')
        if DEBUG:
            dot = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('test_voided_after_block')

        # Verify state after b3:
        # - tx_competitor is now valid (confirmed by b3)
        # - tx_tip is now voided (lost to tx_competitor)
        assert tx_competitor.get_metadata().voided_by is None, "tx_competitor should be valid now"
        assert tx_tip.get_metadata().voided_by == {tx_tip.hash}, "tx_tip should be voided now"

        # tx_tip should NOT be a tip anymore because it's voided
        tips = set(self.mempool_tips.iter(self.tx_storage))
        assert tx_tip not in tips, (
            "tx_tip should NOT be a tip anymore because it became voided."
        )
