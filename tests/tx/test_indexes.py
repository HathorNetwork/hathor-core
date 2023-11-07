import pytest

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.graphviz import GraphvizVisualizer
from hathor.simulator.utils import add_new_block, add_new_blocks, gen_new_tx
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.transaction import Transaction
from hathor.util import iwindows, not_none
from hathor.wallet import Wallet
from tests import unittest
from tests.utils import HAS_ROCKSDB, add_blocks_unlock_reward, add_custom_tx, add_new_tx, get_genesis_key

settings = HathorSettings()


class BaseIndexesTest(unittest.TestCase):
    __test__ = False

    def test_tx_tips_with_conflict(self):
        from hathor.wallet.base_wallet import WalletOutputInfo

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        address = self.get_address(0)
        value = 500

        outputs = [WalletOutputInfo(address=decode_address(address), value=value, timelock=None)]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 2.0
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx1)
        self.assertTrue(self.manager.propagate_tx(tx1, False))
        if self.manager.tx_storage.indexes.mempool_tips is not None:
            self.assertEqual(
                {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
                {tx1.hash}
            )

        outputs = [WalletOutputInfo(address=decode_address(address), value=value, timelock=None)]

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx2.weight = 2.0
        tx2.parents = [tx1.hash] + self.manager.get_new_tx_parents()[1:]
        self.assertIn(tx1.hash, tx2.parents)
        tx2.timestamp = int(self.clock.seconds()) + 1
        self.manager.cpu_mining_service.resolve(tx2)
        self.assertTrue(self.manager.propagate_tx(tx2, False))
        if self.manager.tx_storage.indexes.mempool_tips is not None:
            self.assertEqual(
                {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
                {tx2.hash}
            )

        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.timestamp = tx2.timestamp + 1
        self.assertIn(tx1.hash, tx3.parents)
        self.manager.cpu_mining_service.resolve(tx3)
        self.assertNotEqual(tx2.hash, tx3.hash)
        self.assertTrue(self.manager.propagate_tx(tx3, False))
        self.assertIn(tx3.hash, tx2.get_metadata().conflict_with)
        if self.manager.tx_storage.indexes.mempool_tips is not None:
            self.assertEqual(
                {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
                # XXX: what should we expect here? I don't think we should exclude both tx2 and tx3, but maybe let the
                # function using the index decide
                # {tx1.hash, tx3.hash}
                {tx1.hash}
            )

    def test_tx_tips_voided(self):
        from hathor.wallet.base_wallet import WalletOutputInfo

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        address1 = self.get_address(0)
        address2 = self.get_address(1)
        address3 = self.get_address(2)
        output1 = WalletOutputInfo(address=decode_address(address1), value=123, timelock=None)
        output2 = WalletOutputInfo(address=decode_address(address2), value=234, timelock=None)
        output3 = WalletOutputInfo(address=decode_address(address3), value=345, timelock=None)
        outputs = [output1, output2, output3]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 2.0
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx1)
        self.assertTrue(self.manager.propagate_tx(tx1, False))
        if self.manager.tx_storage.indexes.mempool_tips is not None:
            self.assertEqual(
                {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
                {tx1.hash}
            )

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx2.weight = 2.0
        tx2.parents = [tx1.hash] + self.manager.get_new_tx_parents()[1:]
        self.assertIn(tx1.hash, tx2.parents)
        tx2.timestamp = int(self.clock.seconds()) + 1
        self.manager.cpu_mining_service.resolve(tx2)
        self.assertTrue(self.manager.propagate_tx(tx2, False))
        if self.manager.tx_storage.indexes.mempool_tips is not None:
            self.assertEqual(
                {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
                {tx2.hash}
            )

        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.weight = 3.0
        # tx3.timestamp = tx2.timestamp + 1
        tx3.parents = tx1.parents
        # self.assertIn(tx1.hash, tx3.parents)
        self.manager.cpu_mining_service.resolve(tx3)
        self.assertNotEqual(tx2.hash, tx3.hash)
        self.assertTrue(self.manager.propagate_tx(tx3, False))
        # self.assertIn(tx3.hash, tx2.get_metadata().voided_by)
        self.assertIn(tx3.hash, tx2.get_metadata().conflict_with)
        if self.manager.tx_storage.indexes.mempool_tips is not None:
            self.assertEqual(
                {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
                # XXX: what should we expect here? I don't think we should exclude both tx2 and tx3, but maybe let the
                # function using the index decide
                {tx1.hash, tx3.hash}
            )

    def test_genesis_not_in_mempool(self):
        if self.tx_storage.indexes.mempool_tips is not None:
            mempool_txs = list(self.tx_storage.indexes.mempool_tips.iter_all(self.tx_storage))
        else:
            mempool_txs = list(self.tx_storage.iter_mempool_from_tx_tips())
        for tx in self.genesis_txs:
            self.assertNotIn(tx, mempool_txs)

    def _test_confirmed_tx_that_spends_unconfirmed_tx(self, debug=False):
        """
          B ────╮────╮
          A ───vv    v
          C ~~> D -> E

        debug=True is only useful to debug the base and dag setup, it will break the test
        """
        from hathor.transaction import Block, TxInput, TxOutput
        from hathor.transaction.scripts import P2PKH
        from hathor.wallet.base_wallet import WalletOutputInfo

        # ---
        # BEGIN SETUP BASE
        # make some outputs to be spent by A, B and C, and also save some addresses blocks/txs to be used later
        add_new_blocks(self.manager, 5, advance_clock=15)
        block0 = add_blocks_unlock_reward(self.manager)[-1]
        self.wallet.unlock(b'123')
        self.wallet.generate_keys()
        address = list(self.wallet.keys.keys())[0]
        baddress = decode_address(address)
        private_key = self.wallet.get_private_key(address)
        tx0 = self.manager.wallet.prepare_transaction_compute_inputs(
            Transaction,
            [
                WalletOutputInfo(address=baddress, value=10, timelock=None),
                WalletOutputInfo(address=baddress, value=10, timelock=None),
                WalletOutputInfo(address=baddress, value=10, timelock=None),
            ],
            self.manager.tx_storage,
        )
        tx0.weight = 1.0
        tx0.parents = self.manager.get_new_tx_parents()
        tx0.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx0)
        # XXX: tx0.outputs[0] is always the change output for some reason
        self.assertEqual(len(tx0.outputs), 4)
        self.assertEqual(tx0.outputs[1], tx0.outputs[2])
        self.assertEqual(tx0.outputs[1], tx0.outputs[3])
        self.assertTrue(self.manager.propagate_tx(tx0, False))
        parents0 = [tx0.hash, tx0.parents[0]]
        # END SETUP BASE

        # ---
        # BEGIN SETUP DAG
        # tx_A: ordinary transaction
        self.tx_A = Transaction(
            timestamp=(tx0.timestamp + 1),
            weight=1.0,
            inputs=[TxInput(tx0.hash, 1, b'')],
            outputs=[TxOutput(10, P2PKH.create_output_script(baddress))],
            parents=list(parents0),
            storage=self.tx_storage,
        )
        self.tx_A.inputs[0].data = P2PKH.create_input_data(
            *self.wallet.get_input_aux_data(self.tx_A.get_sighash_all(), private_key)
        )
        self.manager.cpu_mining_service.resolve(self.tx_A)
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_A, False))
            self.assertFalse(self.tx_A.get_metadata().voided_by)

        # tx_B: ordinary transaction, not related to tx_A
        self.tx_B = Transaction(
            timestamp=(tx0.timestamp + 1),
            weight=1.0,
            inputs=[TxInput(tx0.hash, 2, b'')],
            outputs=[TxOutput(10, P2PKH.create_output_script(baddress))],
            parents=list(parents0),
            storage=self.tx_storage,
        )
        self.tx_B.inputs[0].data = P2PKH.create_input_data(
            *self.wallet.get_input_aux_data(self.tx_B.get_sighash_all(), private_key)
        )
        self.manager.cpu_mining_service.resolve(self.tx_B)
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_B, False))
            self.assertFalse(self.tx_B.get_metadata().voided_by)
            self.assertFalse(self.tx_A.get_metadata().conflict_with)
            self.assertFalse(self.tx_B.get_metadata().conflict_with)

        # tx_C: tip transaction, not related to tx_A or tx_B, must not be the parent of any tx/block
        self.tx_C = Transaction(
            timestamp=(tx0.timestamp + 1),
            weight=1.0,
            inputs=[TxInput(tx0.hash, 3, b'')],
            outputs=[TxOutput(10, P2PKH.create_output_script(baddress))],
            parents=list(parents0),
            storage=self.tx_storage,
        )
        self.tx_C.inputs[0].data = P2PKH.create_input_data(
            *self.wallet.get_input_aux_data(self.tx_C.get_sighash_all(), private_key)
        )
        self.manager.cpu_mining_service.resolve(self.tx_C)
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_C, False))
            self.assertFalse(self.tx_C.get_metadata().voided_by)
            self.assertFalse(self.tx_A.get_metadata().conflict_with)
            self.assertFalse(self.tx_B.get_metadata().conflict_with)
            self.assertFalse(self.tx_C.get_metadata().conflict_with)

        # tx_D: has tx_A and tx_B as parents, but spends from tx_C, confirmed by block_E
        self.tx_D = Transaction(
            timestamp=(self.tx_A.timestamp + 1),
            weight=1.0,
            inputs=[
                TxInput(self.tx_A.hash, 0, b''),
                TxInput(self.tx_B.hash, 0, b''),
                TxInput(self.tx_C.hash, 0, b''),
            ],
            outputs=[TxOutput(30, P2PKH.create_output_script(baddress))],
            parents=[self.tx_A.hash, self.tx_B.hash],
            storage=self.tx_storage,
        )
        for i in range(3):
            self.tx_D.inputs[i].data = P2PKH.create_input_data(
                *self.wallet.get_input_aux_data(self.tx_D.get_sighash_all(), private_key)
            )
        self.manager.cpu_mining_service.resolve(self.tx_D)
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_D, False))
            self.assertFalse(self.tx_D.get_metadata().voided_by)

        # block_E: has tx_D as parent (and also tx_A, to fill it up, but MUST NOT confirm tx_C
        self.block_E = Block(
            timestamp=(self.tx_D.timestamp + 1),
            outputs=[TxOutput(6400, P2PKH.create_output_script(baddress))],
            parents=[block0.hash, self.tx_D.hash, self.tx_B.hash],
            weight=1.0,
            storage=self.tx_storage,
        )
        self.manager.cpu_mining_service.resolve(self.block_E)
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.block_E, False))
            self.assertFalse(self.block_E.get_metadata().voided_by)
            tips = [x.data for x in self.tx_storage.get_all_tips()]
            self.assertEqual(set(tips), {self.tx_C.hash, self.block_E.hash})
        # END SETUP DAG

        # ---
        # BEGIN TEST INDEX BEHAVIOR
        # order of operations to simulate what will happen on sync-v2 and what we want to avoid:
        deps_index = self.manager.tx_storage.indexes.deps

        # - add block_E to deps-index, it should then say tx_D and tx_B are needed
        self.assertFalse(self.block_E.get_metadata().validation.is_fully_connected())
        deps_index.add_tx(self.block_E)
        self.assertEqual(
            set(deps_index._iter_needed_txs()),
            {self.tx_D.hash, self.tx_B.hash},
        )

        # - add tx_D to deps-index, it should now say tx_A, tx_B and most importantly tx_C are needed
        self.assertFalse(self.tx_D.get_metadata().validation.is_fully_connected())
        deps_index.add_tx(self.tx_D)
        deps_index.remove_from_needed_index(self.tx_D.hash)
        # XXX: the next assert will fail when the index does not use tx.get_all_dependencies()
        self.assertEqual(
            set(deps_index._iter_needed_txs()),
            {self.tx_A.hash, self.tx_B.hash, self.tx_C.hash},
        )
        # END TEST INDEX BEHAVIOR

    def test_utxo_index_genesis(self):
        from hathor.indexes.utxo_index import UtxoIndexItem
        from tests.utils import GENESIS_ADDRESS_B58

        HTR_UID = settings.HATHOR_TOKEN_UID

        assert self.tx_storage.indexes is not None
        utxo_index = self.tx_storage.indexes.utxo

        # let's check everything is alright, all UTXOs should currently be from just the mined blocks and genesis
        expected_genesis_utxos = [
            UtxoIndexItem(
                token_uid=HTR_UID,
                tx_id=settings.GENESIS_BLOCK_HASH,
                index=0,
                address=GENESIS_ADDRESS_B58,
                amount=settings.GENESIS_TOKENS,
                timelock=None,
                heightlock=settings.REWARD_SPEND_MIN_BLOCKS,
            ),
        ]

        # height just not enough should be empty
        self.assertEqual(
            list(utxo_index.iter_utxos(address=GENESIS_ADDRESS_B58, token_uid=settings.HATHOR_TOKEN_UID,
                                       target_amount=settings.GENESIS_TOKEN_UNITS,
                                       target_height=settings.REWARD_SPEND_MIN_BLOCKS - 1)),
            [],
        )

        # height is now enough
        self.assertEqual(
            list(utxo_index.iter_utxos(address=GENESIS_ADDRESS_B58, token_uid=settings.HATHOR_TOKEN_UID,
                                       target_amount=settings.GENESIS_TOKEN_UNITS,
                                       target_height=settings.REWARD_SPEND_MIN_BLOCKS)),
            expected_genesis_utxos,
        )

        # otherwise we can leave out the height and it should give the utxos
        self.assertEqual(
            list(utxo_index.iter_utxos(address=GENESIS_ADDRESS_B58, token_uid=settings.HATHOR_TOKEN_UID,
                                       target_amount=settings.GENESIS_TOKEN_UNITS)),
            expected_genesis_utxos,
        )

    def test_utxo_index_reorg(self):
        from hathor.indexes.utxo_index import UtxoIndexItem

        assert self.tx_storage.indexes is not None
        utxo_index = self.tx_storage.indexes.utxo

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        address = self.manager.wallet.get_unused_address(mark_as_used=True)
        value = 10

        def check_utxos(*args):
            """Pass a values of tuples (tx_id, index, amount, heightlock)"""
            # target_amount doesn't really matter as long as it is large enough, since we want to see the most UTXOs
            # for the given address that we can
            actual = list(utxo_index.iter_utxos(address=address, target_amount=9999999))
            expected = [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=tx_id,
                    index=index,
                    address=address,
                    amount=amount,
                    timelock=None,
                    heightlock=heightlock,
                ) for tx_id, index, amount, heightlock in args
            ]
            # print('expected = [')
            # for x in expected:
            #     print(f'\t{x!r},')
            # print(']')
            # print('actual = [')
            # for x in actual:
            #     print(f'\t{x!r},')
            # print(']')
            self.assertEqual(actual, expected)

        tx_base = add_new_tx(self.manager, address, value)
        # there will be 2 outputs, the first one is the change, the second one is what we want
        self.assertEqual(len(tx_base.outputs), 2)
        check_utxos((tx_base.hash, 1, value, None))

        # this tx is fine, nothing unusual, it should be added with no problem
        txA1 = add_custom_tx(self.manager, [(tx_base, 1)], n_outputs=1, weight=1.0, resolve=True, address=address)
        self.graphviz.labels[txA1.hash] = 'txA1'
        self.assertFalse(bool(txA1.get_metadata().voided_by))
        check_utxos((txA1.hash, 0, value, None))

        # this is also fine
        txB1 = add_custom_tx(self.manager, [(txA1, 0)], n_outputs=1, weight=1.0, resolve=True, address=address)
        self.graphviz.labels[txB1.hash] = 'txB1'
        self.assertFalse(bool(txB1.get_metadata().voided_by))
        check_utxos((txB1.hash, 0, value, None))

        # add a block to put weight on this branch and force a re-org later with a heavier block
        block1 = add_new_block(self.manager, weight=1.1, address=decode_address(address))
        self.graphviz.labels[block1.hash] = 'block1'
        self.assertFalse(bool(block1.get_metadata().voided_by))
        check_utxos((block1.hash, 0, 6400, 36), (txB1.hash, 0, value, None))

        # this is now in conflict with A1, it should be voided right out of the box
        txA2 = add_custom_tx(self.manager, [(tx_base, 1)], n_outputs=1, weight=1.0, resolve=True, address=address)
        self.graphviz.labels[txA2.hash] = 'txA2'
        self.assertTrue(bool(txA2.get_metadata().voided_by))
        check_utxos((block1.hash, 0, 6400, 36), (txB1.hash, 0, value, None))

        # this one too, although it could also be a tie
        txB2 = add_custom_tx(self.manager, [(txA2, 0)], n_outputs=1, weight=1.0, resolve=True, address=address)
        self.graphviz.labels[txB2.hash] = 'txB2'
        self.assertTrue(bool(txB2.get_metadata().voided_by))

        # double-check that everything is as expected before adding a block that will cause a re-org
        check_utxos((block1.hash, 0, 6400, 36), (txB1.hash, 0, value, None))
        self.assertFalse(bool(txA1.get_metadata().voided_by))
        self.assertFalse(bool(txB1.get_metadata().voided_by))
        self.assertFalse(bool(block1.get_metadata().voided_by))
        self.assertTrue(bool(txA2.get_metadata().voided_by))
        self.assertTrue(bool(txB2.get_metadata().voided_by))

        # now add a block that will cause a re-org
        block2 = self.manager.generate_mining_block(parent_block_hash=block1.parents[0],
                                                    address=decode_address(address))
        block2.parents[1:] = [txA2.hash, txB2.hash]
        block2.timestamp = block1.timestamp
        block2.weight = 1.2
        self.manager.cpu_mining_service.resolve(block2)
        self.manager.verification_service.validate_full(block2)
        self.manager.propagate_tx(block2, fails_silently=False)
        self.graphviz.labels[block2.hash] = 'block2'

        # make sure a reorg did happen as expected
        check_utxos((block2.hash, 0, 6400, 36), (txB2.hash, 0, value, None))
        self.assertTrue(bool(txA1.get_metadata().voided_by))
        self.assertTrue(bool(txB1.get_metadata().voided_by))
        self.assertTrue(bool(block1.get_metadata().voided_by))
        self.assertFalse(bool(block2.get_metadata().voided_by))
        self.assertFalse(bool(txA2.get_metadata().voided_by))
        self.assertFalse(bool(txB2.get_metadata().voided_by))

    def test_utxo_index_simple(self):
        from hathor.indexes.utxo_index import UtxoIndexItem

        assert self.tx_storage.indexes is not None
        utxo_index = self.tx_storage.indexes.utxo

        address = self.get_address(0)

        add_new_blocks(self.manager, 4, advance_clock=1)

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            []
        )

        # Add some blocks with the address that we have, we'll have 4 outputs of 64.00 HTR each, 256.00 HTR in total
        blocks = add_new_blocks(self.manager, 4, advance_clock=1, address=decode_address(address))
        add_blocks_unlock_reward(self.manager)

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.get_metadata().height + settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[:1]
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=6500)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.get_metadata().height + settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[4:1:-1]
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=25600)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.get_metadata().height + settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[::-1]
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=30000)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.get_metadata().height + settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[::-1]
            ]
        )

    def test_utxo_index_limits(self):
        from hathor.indexes.utxo_index import UtxoIndexItem

        _debug = False

        assert self.tx_storage.indexes is not None
        utxo_index = self.tx_storage.indexes.utxo

        address = self.get_address(0)
        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            []
        )

        # generate outputs ranging from 1 to 300, we'll need 1+2+...+300 = 45150, which we can do with 7 blocks, but
        # using 8 just to be safe
        add_new_blocks(self.manager, 8, advance_clock=1)
        add_blocks_unlock_reward(self.manager)

        txs = []
        values = list(range(1, 301))
        for value in values:
            txs.append(add_new_tx(self.manager, address, value))
        assert len(txs) == len(values)
        txs_and_values = list(zip(txs, values))

        # starting from 3, up to 300, we should always get 3 outputs, the one with the exact value and the two next
        # lower values, for example, for target_amount=10, we should get outputs with values 10, 9, 8 in this order,
        # this checks make sure all UTXOs are in the index
        for txs_window in iwindows(txs_and_values, 3):
            target_amount = txs_window[-1][1]
            print('check target_amount =', target_amount)
            expected = [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=tx.hash,
                    index=1,
                    address=address,
                    amount=amount,
                    timelock=None,
                    heightlock=None,
                ) for tx, amount in reversed(txs_window)
            ]
            actual = list(utxo_index.iter_utxos(address=address, target_amount=target_amount))
            if _debug:
                print('expected = [')
                for x in expected:
                    print(f'\t{x!r},')
                print(']')
                print('actual = [')
                for x in actual:
                    print(f'\t{x!r},')
                print(']')
            self.assertEqual(actual, expected)

        # now check that at most 255 utxos will be returned when we check for a large enough amount
        max_outputs = settings.MAX_NUM_OUTPUTS
        actual = list(utxo_index.iter_utxos(address=address, target_amount=sum(range(301))))
        expected = [
            UtxoIndexItem(
                token_uid=settings.HATHOR_TOKEN_UID,
                tx_id=tx.hash,
                index=1,
                address=address,
                amount=amount,
                timelock=None,
                heightlock=None,
            ) for tx, amount in txs_and_values[-1:-(max_outputs + 1):-1]  # these are the last 255 utxos
        ]
        if _debug:
            print('expected = [')
            for x in expected:
                print(f'\t{x!r},')
            print(']')
            print('actual = [')
            for x in actual:
                print(f'\t{x!r},')
            print(']')
        self.assertEqual(actual, expected)

    def test_utxo_index_after_push_tx(self):
        from hathor.indexes.utxo_index import UtxoIndexItem
        from hathor.transaction import TxInput, TxOutput
        from hathor.transaction.scripts import P2PKH

        assert self.tx_storage.indexes is not None
        utxo_index = self.tx_storage.indexes.utxo

        address = self.get_address(0)

        add_new_blocks(self.manager, 4, advance_clock=1)

        # Add some blocks with the address that we have, we'll have 1 output of 64.00 HTR
        blocks = add_new_blocks(self.manager, 1, advance_clock=1, address=decode_address(address))
        self.assertEqual(len(blocks), 1)
        add_blocks_unlock_reward(self.manager)

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.get_metadata().height + settings.REWARD_SPEND_MIN_BLOCKS,
                    ) for b in blocks
            ]
        )

        # spend that utxo and check that it is gone from the index
        address1 = self.get_address(1)

        wallet = self.get_wallet()
        tx1 = Transaction(
            timestamp=int(self.clock.seconds()),
            weight=1.0,
            inputs=[TxInput(blocks[0].hash, 0, b'')],
            outputs=[TxOutput(6400, P2PKH.create_output_script(decode_address(address1)))],
            parents=list(self.manager.get_new_tx_parents()),
            storage=self.tx_storage,
        )
        tx1.inputs[0].data = P2PKH.create_input_data(
            *wallet.get_input_aux_data(tx1.get_sighash_all(), wallet.get_private_key(address))
        )
        self.manager.cpu_mining_service.resolve(tx1)
        self.assertTrue(self.manager.propagate_tx(tx1, False))

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            []
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address1, target_amount=6400)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=tx1.hash,
                    index=0,
                    address=address1,
                    amount=6400,
                    timelock=None,
                    heightlock=None,
                )
            ]
        )

    def test_utxo_index_last(self):
        """
        """
        from hathor.indexes.utxo_index import UtxoIndexItem
        from hathor.transaction import TxInput, TxOutput
        from hathor.transaction.scripts import P2PKH

        assert self.tx_storage.indexes is not None
        utxo_index = self.tx_storage.indexes.utxo

        address = self.get_address(0)

        add_new_blocks(self.manager, 4, advance_clock=1)

        # Add some blocks with the address that we have, we'll have 1 output of 64.00 HTR
        blocks = add_new_blocks(self.manager, 1, advance_clock=1, address=decode_address(address))
        self.assertEqual(len(blocks), 1)
        add_blocks_unlock_reward(self.manager)

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.get_metadata().height + settings.REWARD_SPEND_MIN_BLOCKS,
                    ) for b in blocks
            ]
        )

        # spend that utxo and check that it is gone from the index
        address1 = self.get_address(1)

        change_value = 26
        transfer_value = 6400 - change_value
        wallet = self.get_wallet()
        tx1 = Transaction(
            timestamp=int(self.clock.seconds()),
            weight=1.0,
            inputs=[TxInput(blocks[0].hash, 0, b'')],
            outputs=[TxOutput(change_value, P2PKH.create_output_script(decode_address(address))),
                     TxOutput(transfer_value, P2PKH.create_output_script(decode_address(address1)))],
            parents=list(self.manager.get_new_tx_parents()),
            storage=self.tx_storage,
        )
        tx1.inputs[0].data = P2PKH.create_input_data(
            *wallet.get_input_aux_data(tx1.get_sighash_all(), wallet.get_private_key(address))
        )
        self.manager.cpu_mining_service.resolve(tx1)
        self.assertTrue(self.manager.propagate_tx(tx1, False))

        # querying for exact values

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address1, target_amount=transfer_value)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=tx1.hash,
                    index=1,
                    address=address1,
                    amount=transfer_value,
                    timelock=None,
                    heightlock=None,
                )
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=change_value)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=tx1.hash,
                    index=0,
                    address=address,
                    amount=change_value,
                    timelock=None,
                    heightlock=None,
                )
            ]
        )

        # querying for minimum value, should also return same UTXOs

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address1, target_amount=1)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=tx1.hash,
                    index=1,
                    address=address1,
                    amount=transfer_value,
                    timelock=None,
                    heightlock=None,
                )
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            [
                UtxoIndexItem(
                    token_uid=settings.HATHOR_TOKEN_UID,
                    tx_id=tx1.hash,
                    index=0,
                    address=address,
                    amount=change_value,
                    timelock=None,
                    heightlock=None,
                )
            ]
        )

    def test_addresses_index_empty(self):
        addresses_indexes = self.manager.tx_storage.indexes.addresses
        address = self.get_address(10)
        assert address is not None
        self.assertTrue(addresses_indexes.is_address_empty(address))
        self.assertEqual(addresses_indexes.get_sorted_from_address(address), [])

    def test_addresses_index_last(self):
        """
        See these for more context on why this test was added:
        - https://github.com/HathorNetwork/hathor-core/pull/455
        - https://github.com/HathorNetwork/on-call-incidents/issues/50

        To summarize, the RocksDB implementation had a bug caused by how the key iterator works when it reaches the
        end. It will basically return the "seek key" instead of a "database key", and implementation was expecting only
        a database key, which triggered an assertion error.

        The error can be reproduced using addresses for which the seek would reach the end of the index. Which is
        caused by addresses where the byte values are high, in practice this happens for some multisig addresses.
        """
        from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script

        addresses_indexes = self.manager.tx_storage.indexes.addresses

        # XXX: this artificial address should major (be greater byte-wise) any possible "natural" address
        address = '\x7f' * 34
        self.assertTrue(addresses_indexes.is_address_empty(address))
        self.assertEqual(addresses_indexes.get_sorted_from_address(address), [])

        # XXX: since we didn't add any multisig address, this is guaranteed to be reach the tail end of the index
        assert settings.P2PKH_VERSION_BYTE[0] < settings.MULTISIG_VERSION_BYTE[0]

        # generating a multisig address:
        address = generate_multisig_address(generate_multisig_redeem_script(2, [
            bytes.fromhex('0250bf5890c9c6e9b4ab7f70375d31b827d45d0b7b4e3ba1918bcbe71b412c11d7'),
            bytes.fromhex('02d83dd1e9e0ac7976704eedab43fe0b79309166a47d70ec3ce8bbb08b8414db46'),
        ]))
        assert address is not None

        self.assertTrue(addresses_indexes.is_address_empty(address))
        self.assertEqual(addresses_indexes.get_sorted_from_address(address), [])

    def test_height_index(self):
        from hathor.indexes.height_index import HeightInfo

        # make height 100
        H = 100
        blocks = add_new_blocks(self.manager, H - settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=15)
        height_index = self.manager.tx_storage.indexes.height
        self.assertEqual(height_index.get_height_tip(), HeightInfo(100, blocks[-1].hash))
        self.assertEqual(height_index.get_n_height_tips(1), [HeightInfo(100, blocks[-1].hash)])
        self.assertEqual(height_index.get_n_height_tips(2),
                         [HeightInfo(100, blocks[-1].hash), HeightInfo(99, blocks[-2].hash)])
        self.assertEqual(height_index.get_n_height_tips(3),
                         [HeightInfo(100, blocks[-1].hash),
                          HeightInfo(99, blocks[-2].hash),
                          HeightInfo(98, blocks[-3].hash)])
        self.assertEqual(len(height_index.get_n_height_tips(100)), 100)
        self.assertEqual(len(height_index.get_n_height_tips(101)), 101)
        self.assertEqual(len(height_index.get_n_height_tips(102)), 101)
        self.assertEqual(height_index.get_n_height_tips(103), height_index.get_n_height_tips(104))


class BaseMemoryIndexesTest(BaseIndexesTest):
    def setUp(self):
        from hathor.transaction.storage import TransactionMemoryStorage

        super().setUp()
        self.wallet = Wallet()
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True,
                                        use_memory_index=True, utxo_index=True)
        self.blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = self.blocks[-1]

        self.graphviz = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True)


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class BaseRocksDBIndexesTest(BaseIndexesTest):
    def setUp(self):
        import tempfile

        from hathor.transaction.storage import TransactionRocksDBStorage

        super().setUp()
        self.wallet = Wallet()
        directory = tempfile.mkdtemp()
        self.tmpdirs.append(directory)
        rocksdb_storage = RocksDBStorage(path=directory)
        self.tx_storage = TransactionRocksDBStorage(rocksdb_storage)
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True,
                                        utxo_index=True)
        self.blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = self.blocks[-1]

        self.graphviz = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True)


class SyncV1MemoryIndexesTest(unittest.SyncV1Params, BaseMemoryIndexesTest):
    __test__ = True


class SyncV2MemoryIndexesTest(unittest.SyncV2Params, BaseMemoryIndexesTest):
    __test__ = True

    def test_deps_index(self) -> None:
        from hathor.indexes.memory_deps_index import MemoryDepsIndex

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        # XXX: this test makes use of the internals of the memory deps-index implementation
        deps_index: MemoryDepsIndex = self.manager.tx_storage.indexes.deps

        address = not_none(self.get_address(0))
        value = 500
        tx = gen_new_tx(self.manager, address, value)

        # call add_tx the first time
        deps_index.add_tx(tx)

        # snapshot of state before
        rev_dep_index = deps_index._rev_dep_index.copy()
        txs_with_deps_ready = deps_index._txs_with_deps_ready.copy()
        needed_txs_index = deps_index._needed_txs_index.copy()

        # call add_tx the second time
        deps_index.add_tx(tx)

        # state must not have changed
        self.assertEqual(rev_dep_index, deps_index._rev_dep_index)
        self.assertEqual(txs_with_deps_ready, deps_index._txs_with_deps_ready)
        self.assertEqual(needed_txs_index, deps_index._needed_txs_index)

    def test_confirmed_tx_that_spends_unconfirmed_tx(self):
        self._test_confirmed_tx_that_spends_unconfirmed_tx()


# sync-bridge should behave like sync-v2
class SyncBridgeMemoryIndexesTest(unittest.SyncBridgeParams, SyncV2MemoryIndexesTest):
    pass


class SyncV1RocksDBIndexesTest(unittest.SyncV1Params, BaseRocksDBIndexesTest):
    __test__ = True


class SyncV2RocksDBIndexesTest(unittest.SyncV2Params, BaseRocksDBIndexesTest):
    __test__ = True

    def test_deps_index(self) -> None:
        from hathor.indexes.rocksdb_deps_index import RocksDBDepsIndex

        indexes = self.manager.tx_storage.indexes
        indexes.deps = RocksDBDepsIndex(indexes._db, _force=True)

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        # XXX: this test makes use of the internals of the rocksdb deps-index implementation
        deps_index: RocksDBDepsIndex = self.manager.tx_storage.indexes.deps

        address = not_none(self.get_address(0))
        value = 500
        tx = gen_new_tx(self.manager, address, value)

        # call add_tx the first time
        deps_index.add_tx(tx)

        # snapshot of state before
        db_dict_before = deps_index._clone_into_dict()

        # call add_tx the second time
        deps_index.add_tx(tx)

        # state must not have changed
        db_dict_after = deps_index._clone_into_dict()
        self.assertEqual(db_dict_before, db_dict_after)

    def test_confirmed_tx_that_spends_unconfirmed_tx(self):
        from hathor.indexes.rocksdb_deps_index import RocksDBDepsIndex

        indexes = self.manager.tx_storage.indexes
        indexes.deps = RocksDBDepsIndex(indexes._db, _force=True)
        self._test_confirmed_tx_that_spends_unconfirmed_tx()


# sync-bridge should behave like sync-v2
class SyncBridgeRocksDBIndexesTest(unittest.SyncBridgeParams, SyncV2RocksDBIndexesTest):
    pass
