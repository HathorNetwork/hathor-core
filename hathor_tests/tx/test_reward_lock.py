import pytest

from hathor.crypto.util import get_address_b58_from_bytes, get_address_from_public_key
from hathor.exception import InvalidNewTransaction
from hathor.graphviz import GraphvizVisualizer
from hathor.manager import HathorManager
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import RewardLocked
from hathor.transaction.scripts import P2PKH
from hathor.wallet import Wallet
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.utils import add_blocks_unlock_reward, get_genesis_key

DEBUG: bool = False


class TransactionTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.wallet = Wallet()

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.tx_storage = self.create_tx_storage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True)
        blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = blocks[-1]

    def _add_reward_block(self) -> tuple[Block, int]:
        reward_block = self.manager.generate_mining_block(
            address=get_address_from_public_key(self.genesis_public_key)
        )
        self.manager.cpu_mining_service.resolve(reward_block)
        self.assertTrue(self.manager.propagate_tx(reward_block))
        # XXX: calculate unlock height AFTER adding the block so the height is correctly calculated
        unlock_height = reward_block.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS + 1
        return reward_block, unlock_height

    def _spend_reward_tx(self, manager: HathorManager, reward_block: Block) -> tuple[Transaction, str]:
        value = reward_block.outputs[0].value
        assert manager.wallet is not None
        address = manager.wallet.get_unused_address_bytes()
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
        tx.init_static_metadata_from_storage(self._settings, self.tx_storage)
        return tx, get_address_b58_from_bytes(address)

    def test_classic_reward_lock(self) -> None:
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # reward cannot be spent while not enough blocks are added
        for _ in range(self._settings.REWARD_SPEND_MIN_BLOCKS):
            tx, _ = self._spend_reward_tx(self.manager, reward_block)
            self.assertEqual(tx.static_metadata.min_height, unlock_height)
            with self.assertRaises(RewardLocked):
                self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))
            add_new_blocks(self.manager, 1, advance_clock=1)

        # now it should be spendable
        tx, _ = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.static_metadata.min_height, unlock_height)
        self.assertTrue(self.manager.propagate_tx(tx))

    def test_block_with_not_enough_height(self) -> None:
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add one less block than needed
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS - 1, advance_clock=1)

        # add tx bypassing reward-lock verification
        # XXX: this situation is impossible in practice, but we force it to test that when a block tries to confirm a
        #      transaction before it can the RewardLocked exception is raised
        tx, _ = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.static_metadata.min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx, reject_locked_reward=False))

        # new block will try to confirm it and fail
        with pytest.raises(InvalidNewTransaction) as e:
            add_new_blocks(self.manager, 1, advance_clock=1)

        assert isinstance(e.value.__cause__, RewardLocked)

        # check that the last block was not added to the storage
        all_blocks = [vertex for vertex in self.manager.tx_storage.get_all_transactions() if vertex.is_block]
        assert len(all_blocks) == 2 * self._settings.REWARD_SPEND_MIN_BLOCKS + 1

    def test_block_with_enough_height(self) -> None:
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add just enough blocks
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1)

        # add tx that spends the reward
        tx, _ = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.static_metadata.min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx))

        # new block will be able to confirm it
        add_new_blocks(self.manager, 1, advance_clock=1)

    def test_mempool_tx_with_not_enough_height(self) -> None:
        from hathor.exception import InvalidNewTransaction

        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add one less block than needed
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS - 1, advance_clock=1)

        # add tx to mempool, must fail reward-lock verification
        tx, _ = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.static_metadata.min_height, unlock_height)
        with self.assertRaises(RewardLocked):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))
        with self.assertRaises(InvalidNewTransaction):
            self.assertTrue(self.manager.on_new_tx(tx))

    def test_mempool_tx_with_enough_height(self) -> None:
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add just enough blocks
        add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1)

        # add tx that spends the reward, must not fail
        tx, _ = self._spend_reward_tx(self.manager, reward_block)
        self.assertEqual(tx.static_metadata.min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx))

    def test_mempool_tx_invalid_after_reorg(self) -> None:
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # add just enough blocks
        blocks = add_new_blocks(self.manager, self._settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1)

        # add tx that spends the reward, must not fail
        tx, tx_address = self._spend_reward_tx(self.manager, reward_block)
        balance_per_address = self.manager.wallet.get_balance_per_address(self._settings.HATHOR_TOKEN_UID)
        assert tx_address not in balance_per_address
        self.assertEqual(tx.static_metadata.min_height, unlock_height)
        self.assertTrue(self.manager.on_new_tx(tx))
        balance_per_address = self.manager.wallet.get_balance_per_address(self._settings.HATHOR_TOKEN_UID)
        assert balance_per_address[tx_address] == 6400

        # re-org: replace last two blocks with one block, new height will be just one short of enough
        block_to_replace = blocks[-2]
        tb0 = self.manager.make_custom_block_template(block_to_replace.parents[0], block_to_replace.parents[1:])
        b0 = tb0.generate_mining_block(self.manager.rng, storage=self.manager.tx_storage)
        b0.weight = 10
        self.manager.cpu_mining_service.resolve(b0)
        self.manager.propagate_tx(b0)
        self.clock.advance(1)

        # now the new tx should not pass verification considering the reward lock
        with self.assertRaises(RewardLocked):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

        # the transaction should have been removed from the mempool
        self.assertNotIn(tx, self.manager.tx_storage.iter_mempool_from_best_index())

        # additionally the transaction should have been marked as invalid and removed from the storage after the re-org
        self.assertTrue(tx.get_metadata().validation.is_invalid())
        self.assertFalse(self.manager.tx_storage.transaction_exists(tx.hash))
        self.assertTrue(bool(tx.get_metadata().voided_by))

        # assert that the tx has been removed from its dependencies' metadata
        for parent_id in tx.parents:
            parent = self.manager.tx_storage.get_transaction(parent_id)
            assert tx.hash not in parent.get_children()

        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            spent_outputs = spent_tx.get_metadata().spent_outputs
            assert len(spent_outputs) == 1
            assert tx.hash not in spent_outputs[0]

        # the balance for the tx_address must have been removed
        balance_per_address = self.manager.wallet.get_balance_per_address(self._settings.HATHOR_TOKEN_UID)
        assert tx_address not in balance_per_address

    @pytest.mark.xfail(reason='this is no longer the case, timestamp will not matter', strict=True)
    def test_classic_reward_lock_timestamp_expected_to_fail(self) -> None:
        # add block with a reward we can spend
        reward_block, unlock_height = self._add_reward_block()

        # we add enough blocks that this output could be spent based on block height
        blocks = add_blocks_unlock_reward(self.manager)

        # tx timestamp is equal to the block that unlock the spent rewards. It should
        # be greater, so it'll fail
        tx, _ = self._spend_reward_tx(self.manager, reward_block)
        tx.timestamp = blocks[-1].timestamp
        self.manager.cpu_mining_service.resolve(tx)
        self.assertEqual(tx.static_metadata.min_height, unlock_height)
        with self.assertRaises(RewardLocked):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_removed_tx_confirmed_by_orphan_block(self) -> None:
        manager = self.create_peer('unittests')
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            blockchain b9 a[10..10]
            b10 < dummy

            # tx1 spends a reward that's unlocked by 1 block
            b11 < tx1
            b1.out[0] <<< tx1
            tx1 <-- b12

            # a10 causes a reorg and replaces b10-b12, invalidating tx1
            a10.weight = 10
            b12 < a10
        ''')

        tx1, = artifacts.get_typed_vertices(['tx1'], Transaction)
        b12, a10 = artifacts.get_typed_vertices(['b12', 'a10'], Block)

        artifacts.propagate_with(manager, up_to='b12')
        if DEBUG:
            dot = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-b12')

        assert b12.get_metadata().validation.is_valid()
        assert b12.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block == b12.hash
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(manager, up_to='a10')
        if DEBUG:
            dot = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True).dot()
            dot.render('after-a10')

        assert b12.get_metadata().validation.is_invalid()
        assert b12.get_metadata().voided_by == {b12.hash, self._settings.PARTIALLY_VALIDATED_ID}

        assert a10.get_metadata().validation.is_valid()
        assert a10.get_metadata().voided_by is None

        assert tx1.get_metadata().first_block is None
        assert tx1.get_metadata().validation.is_invalid()
        assert tx1.get_metadata().voided_by == {self._settings.PARTIALLY_VALIDATED_ID}

        assert tx1 not in manager.tx_storage.iter_mempool_from_best_index()
        assert not manager.tx_storage.transaction_exists(tx1.hash)
        assert not manager.tx_storage.transaction_exists(b12.hash)
