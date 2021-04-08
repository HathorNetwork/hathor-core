import random

import pytest
from mnemonic import Mnemonic

from hathor.daa import TestMode, _set_test_mode
from hathor.graphviz import GraphvizVisualizer
from hathor.simulator import FakeConnection
from hathor.wallet import HDWallet
from tests import unittest
from tests.utils import add_blocks_unlock_reward, add_new_block, add_new_double_spending, add_new_transactions


class BaseHathorSyncMethodsTestCase(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        # import sys
        # from twisted.python import log
        # log.startLogging(sys.stdout)

        # self.set_random_seed(0)

        from hathor.transaction.genesis import _get_genesis_transactions_unsafe
        first_timestamp = min(tx.timestamp for tx in _get_genesis_transactions_unsafe(None))
        self.clock.advance(first_timestamp + random.randint(3600, 120*24*3600))

        self.network = 'testnet'

    def create_peer(self, network, unlock_wallet=True):
        wallet = HDWallet(gap_limit=2)
        wallet._manually_initialize()

        _set_test_mode(TestMode.TEST_ALL_WEIGHT)
        manager = super().create_peer(network, wallet=wallet)
        manager.avg_time_between_blocks = 64

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(bytes(random.randint(0, 255) for _ in range(32)))
        wallet.unlock(words=words, tx_storage=manager.tx_storage)
        return manager

    def test_split_brain_only_blocks_different_height(self):
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        manager1.avg_time_between_blocks = 3

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        manager2.avg_time_between_blocks = 3

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            add_blocks_unlock_reward(manager2)
            self.clock.advance(10)

        # Add one more block to manager1, so it's the winner chain
        add_new_block(manager1, advance_clock=1)

        height_cache_manager1 = manager1.tx_storage._block_height_index._index

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

        self.assertCountEqual(height_cache_manager1, manager1.tx_storage._block_height_index._index)
        self.assertCountEqual(height_cache_manager1, manager2.tx_storage._block_height_index._index)

    # XXX We must decide what to do when different chains have the same score
    # For now we are voiding everyone until the first common block
    def test_split_brain_only_blocks_same_height(self):
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        manager1.avg_time_between_blocks = 3

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        manager2.avg_time_between_blocks = 3

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            unlock_reward_blocks1 = add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            unlock_reward_blocks2 = add_blocks_unlock_reward(manager2)
            self.clock.advance(10)

        block_tips1 = unlock_reward_blocks1[-1].hash
        block_tips2 = unlock_reward_blocks2[-1].hash

        self.assertEqual(len(manager1.tx_storage.get_best_block_tips()), 1)
        self.assertCountEqual(manager1.tx_storage.get_best_block_tips(), {block_tips1})
        self.assertEqual(len(manager2.tx_storage.get_best_block_tips()), 1)
        self.assertCountEqual(manager2.tx_storage.get_best_block_tips(), {block_tips2})

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

        self.assertEqual(len(manager1.tx_storage.get_best_block_tips()), 2)
        self.assertCountEqual(manager1.tx_storage.get_best_block_tips(), {block_tips1, block_tips2})
        self.assertEqual(len(manager2.tx_storage.get_best_block_tips()), 2)
        self.assertCountEqual(manager2.tx_storage.get_best_block_tips(), {block_tips1, block_tips2})

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

        # Both chains have the same height and score
        # so they will void all blocks and keep only the genesis (the common block and txs)
        self.assertEqual(len(winners1_after), 3)
        self.assertEqual(len(winners2_after), 3)

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

        if new_block.get_block_parent().hash == block_tips1:
            winners = winners1
        else:
            winners = winners2

        self.assertCountEqual(winners, winners1_after)
        self.assertCountEqual(winners, winners2_after)

        self.assertEqual(len(manager1.tx_storage.get_best_block_tips()), 1)
        self.assertCountEqual(manager1.tx_storage.get_best_block_tips(), {new_block.hash})
        self.assertEqual(len(manager2.tx_storage.get_best_block_tips()), 1)
        self.assertCountEqual(manager2.tx_storage.get_best_block_tips(), {new_block.hash})

    def test_split_brain_only_blocks_bigger_score(self):
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        manager1.avg_time_between_blocks = 3

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        manager2.avg_time_between_blocks = 3

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
        b.resolve()
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


class SyncV1HathorSyncMethodsTestCase(unittest.SyncV1Params, BaseHathorSyncMethodsTestCase):
    __test__ = True

    def test_split_brain_plain(self):
        # XXX This test still needs some discussion. It's failing we are not propagating
        # the voided_by info to the tx children when we have a conflict tx
        # Because of that it fails the assert where all parents voided_by should be a
        # subset of the children voided_by
        debug_pdf = False

        manager1 = self.create_peer(self.network, unlock_wallet=True)
        manager1.avg_time_between_blocks = 3

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        manager2.avg_time_between_blocks = 3

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            add_blocks_unlock_reward(manager2)
            self.clock.advance(10)
            for _ in range(random.randint(3, 10)):
                add_new_transactions(manager1, random.randint(2, 4), advance_clock=1)
                add_new_transactions(manager2, random.randint(3, 7), advance_clock=1)
                add_new_double_spending(manager1)

                add_new_double_spending(manager2)
                self.clock.advance(10)

        self.clock.advance(20)

        add_new_block(manager1, advance_clock=1)

        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True).dot()
            dot1.render('dot1-pre')

        conn = FakeConnection(manager1, manager2)

        # upper limit to how many steps it definitely should be enough
        for i in range(5000):
            if conn.synced_or_error():
                break
            conn.run_one_step()
            self.clock.advance(1)
        else:
            # error if we fall off the loop without breaking
            self.fail('took more steps than expected')
        self.log.debug('steps', count=i)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True).dot()
            dot1.render('dot1-post')
            dot2 = GraphvizVisualizer(manager2.tx_storage, include_verifications=True).dot()
            dot2.render('dot2-post')

        # node_sync = conn.proto1.state.sync_manager
        # self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        # self.assertTipsEqual(manager1, manager2)
        self.assertConsensusEqual(manager1, manager2)
        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)


class SyncV2HathorSyncMethodsTestCase(unittest.SyncV2Params, BaseHathorSyncMethodsTestCase):
    __test__ = True

    # XXX: should test_split_brain be ported to sync-v2?

    def test_split_brain_no_double_spending(self):
        manager1 = self.create_peer(self.network, unlock_wallet=True)
        manager1.avg_time_between_blocks = 3

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        manager2.avg_time_between_blocks = 3

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
            for _ in range(random.randint(3, 10)):
                add_new_transactions(manager1, random.randint(2, 4), advance_clock=1)
                txs = add_new_transactions(manager2, random.randint(3, 7), advance_clock=1)
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

        # upper limit to how many steps it definitely should be enough
        for i in range(5000):
            if conn.synced_or_error():
                break
            conn.run_one_step()
            self.clock.advance(1)
        else:
            # error if we fall off the loop without breaking
            self.fail('took more steps than expected')

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


# sync-bridge should behave like sync-v2
class SyncBridgeHathorSyncMethodsTestCase(unittest.SyncBridgeParams, SyncV2HathorSyncMethodsTestCase):
    pass
