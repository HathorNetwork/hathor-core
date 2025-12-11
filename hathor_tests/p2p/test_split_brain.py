import pytest
from mnemonic import Mnemonic

from hathor.daa import TestMode
from hathor.graphviz import GraphvizVisualizer
from hathor.manager import HathorManager
from hathor.simulator import FakeConnection
from hathor.simulator.utils import add_new_block
from hathor.transaction import Block
from hathor.util import not_none
from hathor.wallet import HDWallet
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_double_spending, add_new_transactions


def select_best_block(b1: Block, b2: Block) -> Block:
    """This function returns the best block according to score and using hash as tiebreaker."""
    meta1 = b1.get_metadata()
    meta2 = b2.get_metadata()
    if meta1.score == meta2.score:
        if b1.hash < b2.hash:
            return b1
        else:
            return b2
    else:
        if meta1.score > meta2.score:
            return b1
        else:
            return b2


class SyncMethodsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        first_timestamp = self._settings.GENESIS_BLOCK_TIMESTAMP
        self.clock.advance(first_timestamp + self.rng.randint(3600, 120*24*3600))

        self.network = 'testnet'

    def create_peer(self, network: str, unlock_wallet: bool = True) -> HathorManager:  # type: ignore[override]
        wallet = HDWallet(gap_limit=2)
        wallet._manually_initialize()

        manager: HathorManager = super().create_peer(network, wallet=wallet)
        manager.daa.TEST_MODE = TestMode.TEST_ALL_WEIGHT
        # manager.avg_time_between_blocks = 64  # FIXME: This property is not defined. Fix this test.

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(bytes(self.rng.randint(0, 255) for _ in range(32)))
        wallet.unlock(words=words, tx_storage=manager.tx_storage)
        return manager

    @pytest.mark.slow
    def test_split_brain_plain(self) -> None:
        debug_pdf = False

        manager1 = self.create_peer(self.network, unlock_wallet=True)
        # manager1.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        # manager2.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            add_blocks_unlock_reward(manager2)
            self.clock.advance(10)
            for _ in range(self.rng.randint(3, 10)):
                add_new_transactions(manager1, self.rng.randint(2, 4), advance_clock=1)
                add_new_transactions(manager2, self.rng.randint(3, 7), advance_clock=1)
                add_new_double_spending(manager1)
                add_new_double_spending(manager2)
                self.clock.advance(10)
        self.clock.advance(20)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True).dot()
            dot1.render('dot1-pre')

        self.assertTipsNotEqual(manager1, manager2)
        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        # input('Press enter to continue...')

        conn = FakeConnection(manager1, manager2)

        # upper limit to how many steps it definitely should be enough
        for i in range(3000):
            if not conn.can_step():
                break
            conn.run_one_step()
            self.clock.advance(0.2)
        else:
            # error if we fall off the loop without breaking
            self.fail('took more steps than expected')
        self.log.debug('steps', count=i)
        for i in range(500):
            conn.run_one_step()
            self.clock.advance(0.2)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True).dot()
            dot1.render('dot1-post')
            dot2 = GraphvizVisualizer(manager2.tx_storage, include_verifications=True).dot()
            dot2.render('dot2-post')

        node_sync = conn.proto1.state.sync_agent
        self.assertSyncedProgress(node_sync)
        self.assertTipsEqual(manager1, manager2)
        self.assertConsensusEqual(manager1, manager2)
        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

    @pytest.mark.slow
    def test_split_brain_only_blocks_different_height(self) -> None:
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        # manager1.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        # manager2.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            add_blocks_unlock_reward(manager2)
            self.clock.advance(10)

        # Add one more block to manager1, so it's the winner chain
        add_new_block(manager1, advance_clock=1)

        block_tip1 = not_none(manager1.tx_storage.indexes).height.get_tip()

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        conn = FakeConnection(manager1, manager2)

        empty_counter = 0
        for i in range(1000):
            if conn.is_empty():
                empty_counter += 1
                if empty_counter > 10:
                    break
            else:
                empty_counter = 0

            conn.run_one_step()
            self.clock.advance(1)

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)
        self.assertConsensusEqual(manager1, manager2)

        self.assertEqual(block_tip1, not_none(manager1.tx_storage.indexes).height.get_tip())
        self.assertEqual(block_tip1, not_none(manager2.tx_storage.indexes).height.get_tip())

    def test_split_brain_only_blocks_same_height(self) -> None:
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        manager2 = self.create_peer(self.network, unlock_wallet=True)

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            unlock_reward_blocks1 = add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            unlock_reward_blocks2 = add_blocks_unlock_reward(manager2)
            self.clock.advance(10)

        block_tip1 = unlock_reward_blocks1[-1]
        block_tip2 = unlock_reward_blocks2[-1]
        best_block = select_best_block(block_tip1, block_tip2)

        self.assertCountEqual(manager1.tx_storage.get_best_block_hash(), block_tip1.hash)
        self.assertCountEqual(manager2.tx_storage.get_best_block_hash(), block_tip2.hash)

        # Save winners for manager1 and manager2
        winners1 = set()
        for tx1 in manager1.tx_storage.get_all_transactions():
            tx1_meta = tx1.get_metadata()
            if not tx1_meta.voided_by:
                winners1.add(tx1.hash)

        winners2 = set()
        for tx2 in manager2.tx_storage.get_all_transactions():
            tx2_meta = tx2.get_metadata()
            if not tx2_meta.voided_by:
                winners2.add(tx2.hash)

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        conn = FakeConnection(manager1, manager2)

        empty_counter = 0
        for i in range(1000):
            if conn.is_empty():
                empty_counter += 1
                if empty_counter > 10:
                    break
            else:
                empty_counter = 0

            conn.run_one_step()
            self.clock.advance(1)

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        # XXX: there must always be a single winner, some methods still return containers (set/list/...) because
        #      multiple winners were supported in the past, but those will eventually be refactored
        # import pudb; pu.db
        self.assertCountEqual(manager1.tx_storage.get_best_block_hash(), best_block.hash)
        self.assertCountEqual(manager2.tx_storage.get_best_block_hash(), best_block.hash)

        winners1_after = set()
        for tx1 in manager1.tx_storage.get_all_transactions():
            tx1_meta = tx1.get_metadata()
            if not tx1_meta.voided_by:
                winners1_after.add(tx1.hash)

        winners2_after = set()
        for tx2 in manager2.tx_storage.get_all_transactions():
            tx2_meta = tx2.get_metadata()
            if not tx2_meta.voided_by:
                winners2_after.add(tx2.hash)

        # Both chains have the same height and score, which is of the winner block,
        expected_count = not_none(best_block.get_height()) + 3  # genesis vertices are included
        self.assertEqual(len(winners1_after), expected_count)
        self.assertEqual(len(winners2_after), expected_count)

        new_block = add_new_block(manager1, advance_clock=1)
        self.clock.advance(20)

        empty_counter = 0
        for i in range(500):
            if conn.is_empty():
                empty_counter += 1
                if empty_counter > 10:
                    break
            else:
                empty_counter = 0

            conn.run_one_step()
            self.clock.advance(1)

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        winners1_after = set()
        for tx1 in manager1.tx_storage.get_all_transactions():
            tx1_meta = tx1.get_metadata()
            if not tx1_meta.voided_by:
                winners1_after.add(tx1.hash)

        winners2_after = set()
        for tx2 in manager2.tx_storage.get_all_transactions():
            tx2_meta = tx2.get_metadata()
            if not tx2_meta.voided_by:
                winners2_after.add(tx2.hash)

        winners1.add(new_block.hash)
        winners2.add(new_block.hash)

        if new_block.get_block_parent().hash == block_tip1.hash:
            winners = winners1
        else:
            winners = winners2

        self.assertCountEqual(winners, winners1_after)
        self.assertCountEqual(winners, winners2_after)

        self.assertCountEqual(manager1.tx_storage.get_best_block_hash(), new_block.hash)
        self.assertCountEqual(manager2.tx_storage.get_best_block_hash(), new_block.hash)

    def test_split_brain_only_blocks_bigger_score(self) -> None:
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        # manager1.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        # manager2.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.

        # Start with 1 because of the genesis block
        manager2_blocks = 1
        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            manager2_blocks += 1
            blocks2 = add_blocks_unlock_reward(manager2)
            manager2_blocks += len(blocks2)
            self.clock.advance(10)

        # Add two more blocks to manager1, so it's the winner chain
        add_new_block(manager1, advance_clock=1)
        add_new_block(manager1, advance_clock=1)

        # Propagates a block with bigger weight, so the score of the manager2 chain
        # will be bigger than the other one
        b = add_new_block(manager2, advance_clock=1, propagate=False)
        b.weight = 5
        manager2.cpu_mining_service.resolve(b)
        manager2.propagate_tx(b)
        manager2_blocks += 1

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        conn = FakeConnection(manager1, manager2)

        empty_counter = 0
        for i in range(1000):
            if conn.is_empty():
                empty_counter += 1
                if empty_counter > 10:
                    break
            else:
                empty_counter = 0

            conn.run_one_step()
            self.clock.advance(1)

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)
        self.assertConsensusEqual(manager1, manager2)

        winners2_blocks = 0
        for tx2 in manager2.tx_storage.get_all_transactions():
            tx2_meta = tx2.get_metadata()
            if tx2.is_block and not tx2_meta.voided_by:
                winners2_blocks += 1

        # Assert that the consensus had the manager2 chain
        self.assertEqual(winners2_blocks, manager2_blocks)

    def test_split_brain_no_double_spending(self) -> None:
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        # manager1.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.
        manager1.connections.disable_rate_limiter()

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        # manager2.avg_time_between_blocks = 3  # FIXME: This property is not defined. Fix this test.
        manager2.connections.disable_rate_limiter()

        winner_blocks = 1
        winner_txs = 2

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            winner_blocks += 1
            blocks = add_blocks_unlock_reward(manager2)
            winner_blocks += len(blocks)
            self.clock.advance(10)
            for _ in range(self.rng.randint(3, 10)):
                add_new_transactions(manager1, self.rng.randint(2, 4), advance_clock=1)
                txs = add_new_transactions(manager2, self.rng.randint(3, 7), advance_clock=1)
                winner_txs += len(txs)
                self.clock.advance(10)

        self.clock.advance(20)

        # Manager2 will be the winner because it has the biggest chain
        add_new_block(manager2, advance_clock=1)
        winner_blocks += 1
        self.clock.advance(20)

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        conn = FakeConnection(manager1, manager2)
        # Disable idle timeout.
        conn.disable_idle_timeout()

        self.log.info('starting sync now...')

        # upper limit to how many steps it definitely should be enough
        for i in range(3000):
            if not conn.can_step():
                break
            conn.run_one_step()
            self.clock.advance(1)
        conn.run_until_empty()

        self.log.debug('steps taken', steps=i + 1)

        self.assertConsensusEqual(manager1, manager2)
        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        winners2 = set()
        for tx in manager2.tx_storage.get_all_transactions():
            tx_meta = tx.get_metadata()
            if not tx_meta.voided_by:
                winners2.add(tx.hash)

        self.assertEqual(len(winners2), winner_blocks + winner_txs)
