from hathor.crypto.util import decode_address
from hathor.graphviz import GraphvizVisualizer
from hathor.indexes import RocksDBIndexesManager
from hathor.simulator.utils import add_new_block, add_new_blocks
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.transaction import Transaction
from hathor.transaction.vertex_children import RocksDBVertexChildrenService
from hathor.transaction.vertex_parser import VertexParser, vertex_deserializer
from hathor.util import initialize_hd_wallet, iwindows
from hathor.wallet import Wallet
from hathor_tests import unittest
from hathor_tests.utils import DEFAULT_WORDS, add_blocks_unlock_reward, add_custom_tx, add_new_tx, get_genesis_key


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
        self.assertTrue(self.manager.propagate_tx(tx1))
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
        self.assertTrue(self.manager.propagate_tx(tx2))
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
            {tx2.hash}
        )

        tx3 = vertex_deserializer.deserialize(tx2.get_struct())
        tx3.timestamp = tx2.timestamp + 1
        self.assertIn(tx1.hash, tx3.parents)
        self.manager.cpu_mining_service.resolve(tx3)
        self.assertNotEqual(tx2.hash, tx3.hash)
        self.assertTrue(self.manager.propagate_tx(tx3))
        self.assertIn(tx3.hash, tx2.get_metadata().conflict_with)
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
        self.assertTrue(self.manager.propagate_tx(tx1))
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
        self.assertTrue(self.manager.propagate_tx(tx2))
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
            {tx2.hash}
        )

        tx3 = vertex_deserializer.deserialize(tx2.get_struct())
        tx3.weight = 3.0
        # tx3.timestamp = tx2.timestamp + 1
        tx3.parents = tx1.parents
        # self.assertIn(tx1.hash, tx3.parents)
        self.manager.cpu_mining_service.resolve(tx3)
        self.assertNotEqual(tx2.hash, tx3.hash)
        self.assertTrue(self.manager.propagate_tx(tx3))
        # self.assertIn(tx3.hash, tx2.get_metadata().voided_by)
        self.assertIn(tx3.hash, tx2.get_metadata().conflict_with)
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
            # XXX: what should we expect here? I don't think we should exclude both tx2 and tx3, but maybe let the
            # function using the index decide
            {tx1.hash, tx3.hash}
        )

    def test_genesis_not_in_mempool(self):
        mempool_txs = list(self.tx_storage.indexes.mempool_tips.iter_all(self.tx_storage))
        for tx in self.genesis_txs:
            self.assertNotIn(tx, mempool_txs)

    def test_utxo_index_genesis(self):
        from hathor.indexes.utxo_index import UtxoIndexItem
        from hathor_tests.utils import GENESIS_ADDRESS_B58

        HTR_UID = self._settings.HATHOR_TOKEN_UID
        utxo_index = self.tx_storage.indexes.utxo

        # let's check everything is alright, all UTXOs should currently be from just the mined blocks and genesis
        expected_genesis_utxos = [
            UtxoIndexItem(
                token_uid=HTR_UID,
                tx_id=self._settings.GENESIS_BLOCK_HASH,
                index=0,
                address=GENESIS_ADDRESS_B58,
                amount=self._settings.GENESIS_TOKENS,
                timelock=None,
                heightlock=self._settings.REWARD_SPEND_MIN_BLOCKS,
            ),
        ]

        # height just not enough should be empty
        self.assertEqual(
            list(utxo_index.iter_utxos(address=GENESIS_ADDRESS_B58, token_uid=self._settings.HATHOR_TOKEN_UID,
                                       target_amount=self._settings.GENESIS_TOKEN_UNITS,
                                       target_height=self._settings.REWARD_SPEND_MIN_BLOCKS - 1)),
            [],
        )

        # height is now enough
        self.assertEqual(
            list(utxo_index.iter_utxos(address=GENESIS_ADDRESS_B58, token_uid=self._settings.HATHOR_TOKEN_UID,
                                       target_amount=self._settings.GENESIS_TOKEN_UNITS,
                                       target_height=self._settings.REWARD_SPEND_MIN_BLOCKS)),
            expected_genesis_utxos,
        )

        # otherwise we can leave out the height and it should give the utxos
        self.assertEqual(
            list(utxo_index.iter_utxos(address=GENESIS_ADDRESS_B58, token_uid=self._settings.HATHOR_TOKEN_UID,
                                       target_amount=self._settings.GENESIS_TOKEN_UNITS)),
            expected_genesis_utxos,
        )

    def test_utxo_index_reorg(self):
        from hathor.indexes.utxo_index import UtxoIndexItem
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
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
        block2.timestamp = block1.timestamp + 1
        block2.weight = 4
        self.manager.cpu_mining_service.resolve(block2)
        self.manager.propagate_tx(block2)
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[:1]
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=6500)),
            [
                UtxoIndexItem(
                    token_uid=self._settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[4:1:-1]
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=25600)),
            [
                UtxoIndexItem(
                    token_uid=self._settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[::-1]
            ]
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=30000)),
            [
                UtxoIndexItem(
                    token_uid=self._settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
                ) for b in blocks[::-1]
            ]
        )

    def test_utxo_index_limits(self):
        from hathor.indexes.utxo_index import UtxoIndexItem

        _debug = False
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
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
        max_outputs = self._settings.MAX_NUM_OUTPUTS
        actual = list(utxo_index.iter_utxos(address=address, target_amount=sum(range(301))))
        expected = [
            UtxoIndexItem(
                token_uid=self._settings.HATHOR_TOKEN_UID,
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
                    ) for b in blocks
            ]
        )

        # spend that utxo and check that it is gone from the index
        address1 = self.get_address(1)

        wallet = initialize_hd_wallet(DEFAULT_WORDS)
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
        self.assertTrue(self.manager.propagate_tx(tx1))

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address, target_amount=1)),
            []
        )

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address1, target_amount=6400)),
            [
                UtxoIndexItem(
                    token_uid=self._settings.HATHOR_TOKEN_UID,
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
                    tx_id=b.hash,
                    index=0,
                    address=address,
                    amount=6400,
                    timelock=None,
                    heightlock=b.static_metadata.height + self._settings.REWARD_SPEND_MIN_BLOCKS,
                    ) for b in blocks
            ]
        )

        # spend that utxo and check that it is gone from the index
        address1 = self.get_address(1)

        change_value = 26
        transfer_value = 6400 - change_value
        wallet = initialize_hd_wallet(DEFAULT_WORDS)
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
        self.assertTrue(self.manager.propagate_tx(tx1))

        # querying for exact values

        self.assertEqual(
            list(utxo_index.iter_utxos(address=address1, target_amount=transfer_value)),
            [
                UtxoIndexItem(
                    token_uid=self._settings.HATHOR_TOKEN_UID,
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
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
                    token_uid=self._settings.HATHOR_TOKEN_UID,
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
        self.assertEqual(list(addresses_indexes.get_sorted_from_address(address)), [])

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
        self.assertEqual(list(addresses_indexes.get_sorted_from_address(address)), [])

        # XXX: since we didn't add any multisig address, this is guaranteed to be reach the tail end of the index
        assert self._settings.P2PKH_VERSION_BYTE[0] < self._settings.MULTISIG_VERSION_BYTE[0]

        # generating a multisig address:
        address = generate_multisig_address(generate_multisig_redeem_script(2, [
            bytes.fromhex('0250bf5890c9c6e9b4ab7f70375d31b827d45d0b7b4e3ba1918bcbe71b412c11d7'),
            bytes.fromhex('02d83dd1e9e0ac7976704eedab43fe0b79309166a47d70ec3ce8bbb08b8414db46'),
        ]))
        assert address is not None

        self.assertTrue(addresses_indexes.is_address_empty(address))
        self.assertEqual(list(addresses_indexes.get_sorted_from_address(address)), [])

    def test_height_index(self):
        from hathor.indexes.height_index import HeightInfo

        # make height 100
        H = 100
        blocks = add_new_blocks(self.manager, H - self._settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=15)
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


class RocksDBIndexesTest(BaseIndexesTest):
    __test__ = True

    def setUp(self):
        import tempfile

        from hathor.nanocontracts.storage import NCRocksDBStorageFactory
        from hathor.transaction.storage import TransactionRocksDBStorage

        super().setUp()
        self.wallet = Wallet()
        directory = tempfile.mkdtemp()
        self.tmpdirs.append(directory)
        rocksdb_storage = RocksDBStorage(path=directory)
        parser = VertexParser(settings=self._settings)
        nc_storage_factory = NCRocksDBStorageFactory(rocksdb_storage)
        vertex_children_service = RocksDBVertexChildrenService(rocksdb_storage)
        indexes = RocksDBIndexesManager(rocksdb_storage=rocksdb_storage, settings=self._settings)
        self.tx_storage = TransactionRocksDBStorage(
            reactor=self.reactor,
            rocksdb_storage=rocksdb_storage,
            settings=self._settings,
            vertex_parser=parser,
            nc_storage_factory=nc_storage_factory,
            vertex_children_service=vertex_children_service,
            indexes=indexes,
        )
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
