import pytest

from hathor.crypto.util import get_address_from_public_key
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import RewardLocked
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.wallet import Wallet
from tests import unittest
from tests.utils import add_blocks_unlock_reward, get_genesis_key


class BaseTransactionTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.wallet = Wallet()

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True)
        blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = blocks[-1]

    def _add_reward_block(self):
        reward_block = self.manager.generate_mining_block(
            address=get_address_from_public_key(self.genesis_public_key)
        )
        self.manager.cpu_mining_service.resolve(reward_block)
        self.assertTrue(self.manager.propagate_tx(reward_block))
        # XXX: calculate unlock height AFTER adding the block so the height is correctly calculated
        unlock_height = reward_block.get_metadata().height + self._settings.REWARD_SPEND_MIN_BLOCKS + 1
        return reward_block, unlock_height

    def _spend_reward_tx(self, manager, reward_block):
        value = reward_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        input_ = TxInput(reward_block.hash, 0, b'')
        output = TxOutput(value, script)
        tx = Transaction(
            weight=1,
            timestamp=int(manager.reactor.seconds()) + 1,
            inputs=[input_],
            outputs=[output],
            parents=manager.get_new_tx_parents(),
            storage=manager.tx_storage,
        )
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        input_.data = P2PKH.create_input_data(public_bytes, signature)
        self.manager.cpu_mining_service.resolve(tx)
        tx.update_initial_metadata(save=False)
        return tx

    def test_classic_reward_lock(self):
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # reward cannot be spent while not enough blocks are added
        for _ in range(self._settings.REWARD_SPEND_MIN_BLOCKS):
            tx = self._spend_reward_tx(self.manager, reward_block)
            self.assertEqual(tx.get_metadata().min_height, unlock_height)
            with self.assertRaises(RewardLocked):
                self.manager.verification_service.verify(tx)
            add_new_blocks(self.manager, 1, advance_clock=1)

        # now it should be spendable
        tx = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.get_metadata().min_height, unlock_height)
        self.assertTrue(self.manager.propagate_tx(tx, fails_silently=False))

    def test_block_with_not_enough_height(self):
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add one less block than needed
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS - 1, advance_clock=1)

        # add tx bypassing reward-lock verification
        # XXX: this situation is impossible in practice, but we force it to test that when a block tries to confirms a
        #      transaction before it can the RewardLocked exception is raised
        tx = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.get_metadata().min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx, fails_silently=False, reject_locked_reward=False))

        # new block will try to confirm it and fail
        with self.assertRaises(RewardLocked):
            add_new_blocks(self.manager, 1, advance_clock=1)

    def test_block_with_enough_height(self):
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add just enough blocks
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1)

        # add tx that spends the reward
        tx = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.get_metadata().min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx, fails_silently=False))

        # new block will be able to confirm it
        add_new_blocks(self.manager, 1, advance_clock=1)

    def test_mempool_tx_with_not_enough_height(self):
        from hathor.exception import InvalidNewTransaction

        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add one less block than needed
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS - 1, advance_clock=1)

        # add tx to mempool, must fail reward-lock verification
        tx = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.get_metadata().min_height, unlock_height)
        with self.assertRaises(RewardLocked):
            self.manager.verification_service.verify(tx)
        with self.assertRaises(InvalidNewTransaction):
            self.assertTrue(self.manager.on_new_tx(tx, fails_silently=False))

    def test_mempool_tx_with_enough_height(self):
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add just enough blocks
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1)

        # add tx that spends the reward, must not fail
        tx = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.get_metadata().min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx, fails_silently=False))

    def test_mempool_tx_invalid_after_reorg(self):
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add just enough blocks
        blocks = add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1)

        # add tx that spends the reward, must not fail
        tx = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.get_metadata().min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx, fails_silently=False))

        # re-org: replace last two blocks with one block, new height will be just one short of enough
        block_to_replace = blocks[-2]
        tb0 = self.manager.make_custom_block_template(block_to_replace.parents[0], block_to_replace.parents[1:])
        b0 = tb0.generate_mining_block(self.manager.rng, storage=self.manager.tx_storage)
        b0.weight = 10
        self.manager.cpu_mining_service.resolve(b0)
        self.manager.verification_service.verify(b0)
        self.manager.propagate_tx(b0, fails_silently=False)

        # now the new tx should not pass verification considering the reward lock
        with self.assertRaises(RewardLocked):
            self.manager.verification_service.verify(tx)

        # the transaction should have been removed from the mempool
        self.assertNotIn(tx, self.manager.tx_storage.iter_mempool_from_best_index())

        # additionally the transaction should have been marked as invalid and removed from the storage after the re-org
        self.assertTrue(tx.get_metadata().validation.is_invalid())
        self.assertFalse(self.manager.tx_storage.transaction_exists(tx.hash))

    @pytest.mark.xfail(reason='this is no longer the case, timestamp will not matter', strict=True)
    def test_classic_reward_lock_timestamp_expected_to_fail(self):
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # we add enough blocks that this output could be spent based on block height
        blocks = add_blocks_unlock_reward(self.manager)

        # tx timestamp is equal to the block that unlock the spent rewards. It should
        # be greater, so it'll fail
        tx = self._spend_reward_tx(self.manager, reward_block)
        tx.timestamp = blocks[-1].timestamp
        self.manager.cpu_mining_service.resolve(tx)
        self.assertEqual(tx.get_metadata().min_height, unlock_height)
        with self.assertRaises(RewardLocked):
            self.manager.verification_service.verify(tx)


class SyncV1TransactionTest(unittest.SyncV1Params, BaseTransactionTest):
    __test__ = True


class SyncV2TransactionTest(unittest.SyncV2Params, BaseTransactionTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeTransactionTest(unittest.SyncBridgeParams, SyncV2TransactionTest):
    pass
