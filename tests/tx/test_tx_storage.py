import unittest
import tempfile
import shutil
from hathor.transaction.storage import TransactionJSONStorage, TransactionMemoryStorage, TransactionMetadata
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction import Block, Transaction, TxOutput, TxInput
from hathor.wallet import Wallet, KeyPair


class _BaseTransactionStorageTest:

    class _TransactionStorageTest(unittest.TestCase):
        def setUp(self, tx_storage):
            self.tx_storage = tx_storage
            tx_storage._manually_initialize()
            self.genesis = self.tx_storage.get_all_genesis()
            self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
            self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

            from hathor.p2p.manager import HathorManager
            from hathor.wallet import Wallet
            self.tmpdir = tempfile.mkdtemp(dir='/tmp/')
            wallet = Wallet(directory=self.tmpdir)
            wallet.unlock('teste')
            self.manager = HathorManager(tx_storage=self.tx_storage, wallet=wallet)

            block_parents = [tx.hash for tx in self.genesis]
            output = TxOutput(200, bytes.fromhex('1e393a5ce2ff1c98d4ff6892f2175100f2dad049'))
            self.block = Block(
                timestamp=1535885967,
                weight=12,
                outputs=[output],
                parents=block_parents,
                nonce=100781,
                storage=tx_storage
            )
            self.block.resolve()

            tx_parents = [tx.hash for tx in self.genesis_txs]
            tx_input = TxInput(
                tx_id=bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902'),
                index=0,
                data=bytes.fromhex('46304402203470cb9818c9eb842b0c433b7e2b8aded0a51f5903e971649e870763d0266a'
                                   'd2022049b48e09e718c4b66a0f3178ef92e4d60ee333d2d0e25af8868acf5acbb35aaa583'
                                   '056301006072a8648ce3d020106052b8104000a034200042ce7b94cba00b654d4308f8840'
                                   '7345cacb1f1032fb5ac80407b74d56ed82fb36467cb7048f79b90b1cf721de57e942c5748'
                                   '620e78362cf2d908e9057ac235a63')
            )

            self.tx = Transaction(
                timestamp=1535886380,
                weight=10,
                nonce=932049,
                inputs=[tx_input],
                outputs=[output],
                parents=tx_parents,
                storage=tx_storage
            )
            self.tx.resolve()

        def tearDown(self):
            shutil.rmtree(self.tmpdir)

        def test_genesis(self):
            self.assertEqual(1, len(self.genesis_blocks))
            self.assertEqual(2, len(self.genesis_txs))
            self.assertEqual(1, len(self.genesis_blocks[0].outputs))
            for tx in self.genesis:
                tx.verify()

            for tx in self.genesis:
                self.tx_storage.get_transaction_by_hash(tx.hash.hex())
                self.tx_storage.get_transaction_by_hash_bytes(tx.hash)
                self.assertTrue(self.tx_storage.transaction_exists_by_hash_bytes(tx.hash))
                self.assertTrue(self.tx_storage.transaction_exists_by_hash(tx.hash.hex()))

        def test_storage_basic(self):
            self.assertEqual(1, self.tx_storage.get_block_count())
            self.assertEqual(2, self.tx_storage.get_tx_count())

            block_parents_hash = self.tx_storage.get_tip_blocks_hashes()
            self.assertEqual(1, len(block_parents_hash))
            self.assertEqual(block_parents_hash[0], self.genesis_blocks[0].hash)

            tx_parents_hash = self.tx_storage.get_tip_transactions_hashes()
            self.assertEqual(2, len(tx_parents_hash))
            self.assertEqual(set(tx_parents_hash), {self.genesis_txs[0].hash, self.genesis_txs[1].hash})

        def validate_save(self, obj):
            self.tx_storage.save_transaction(obj)

            loaded_obj1 = self.tx_storage.get_transaction_by_hash_bytes(obj.hash)

            self.assertTrue(self.tx_storage.transaction_exists_by_hash_bytes(obj.hash))

            self.assertEqual(obj, loaded_obj1)
            self.assertEqual(obj.is_block, loaded_obj1.is_block)

            loaded_obj2 = self.tx_storage.get_transaction_by_hash(obj.hash.hex())

            self.assertEqual(obj, loaded_obj2)
            self.assertEqual(obj.is_block, loaded_obj2.is_block)

        def test_save_block(self):
            self.validate_save(self.block)

        def test_save_tx(self):
            self.validate_save(self.tx)

        def test_get_wrong_tx(self):
            hex_error = '00001c5c0b69d13b05534c94a69b2c8272294e6b0c536660a3ac264820677024'
            with self.assertRaises(TransactionDoesNotExist):
                self.tx_storage.get_transaction_by_hash(hex_error)

        def test_save_metadata(self):
            metadata = TransactionMetadata(
                spent_outputs=[1],
                hash=self.genesis_blocks[0].hash
            )
            self.tx_storage.save_metadata(metadata)
            metadata_read = self.tx_storage.get_metadata_by_hash_bytes(self.genesis_blocks[0].hash)
            self.assertEqual(metadata, metadata_read)

        def test_get_latest_blocks(self):
            self.tx_storage.save_transaction(self.block)

            latest_blocks = self.tx_storage.get_latest_blocks(count=3)

            self.assertEqual(len(latest_blocks), 2)
            self.assertEqual(latest_blocks[0].hash, self.block.hash)
            self.assertEqual(latest_blocks[1].hash, self.genesis_blocks[0].hash)

        def test_get_latest_tx(self):
            self.tx_storage.save_transaction(self.tx)

            latest_tx = self.tx_storage.get_latest_transactions(count=3)

            self.assertEqual(len(latest_tx), 3)
            self.assertEqual(latest_tx[0].hash, self.tx.hash)
            self.assertEqual(latest_tx[1].hash, self.genesis_txs[1].hash)
            self.assertEqual(latest_tx[2].hash, self.genesis_txs[0].hash)

        def test_storage_new_blocks(self):
            tip_blocks = self.tx_storage.get_tip_blocks_hashes()
            self.assertEqual(tip_blocks, [self.genesis_blocks[0].hash])

            block1 = self._add_new_block()
            tip_blocks = self.tx_storage.get_tip_blocks_hashes()
            self.assertEqual(tip_blocks, [block1.hash])

            block2 = self._add_new_block()
            tip_blocks = self.tx_storage.get_tip_blocks_hashes()
            self.assertEqual(tip_blocks, [block2.hash])

            # Block3 has the same parents as block2.
            block3 = self._add_new_block(parents=block2.parents)
            tip_blocks = self.tx_storage.get_tip_blocks_hashes()
            self.assertEqual(set(tip_blocks), {block2.hash, block3.hash})

            # Re-generate caches to test topological sort.
            self.tx_storage._manually_initialize()
            tip_blocks = self.tx_storage.get_tip_blocks_hashes()
            self.assertEqual(set(tip_blocks), {block2.hash, block3.hash})

            # Block4 has both blocks as parents
            block4 = self._add_new_block()
            tip_blocks = self.tx_storage.get_tip_blocks_hashes()
            self.assertEqual(tip_blocks, [block4.hash])

        def _add_new_block(self, parents=None):
            block = self.manager.generate_mining_block()
            if parents is not None:
                block.parents = parents
            block.weight = 10
            self.assertTrue(block.resolve())
            self.manager.tx_storage.save_transaction(block)
            return block

        def _create_wallet(self):
            keys = {}
            for _i in range(20):
                keypair = KeyPair.create(b'MYPASS')
                keys[keypair.address] = keypair
            return Wallet(keys=keys)


class TransactionJSONStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir='/tmp/')
        super().setUp(TransactionJSONStorage(self.directory))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class TransactionMemoryStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        super().setUp(TransactionMemoryStorage())
