import shutil
import tempfile
import time
from itertools import chain

from twisted.internet.defer import gatherResults, inlineCallbacks
from twisted.internet.threads import deferToThread

from hathor.daa import TestMode
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.validation_state import ValidationState
from hathor_tests import unittest
from hathor_tests.unittest import TestBuilder
from hathor_tests.utils import BURN_ADDRESS, add_blocks_unlock_reward, add_new_transactions, create_tokens


class BaseTransactionStorageTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.tmpdir = tempfile.mkdtemp()

        builder = TestBuilder()
        builder.enable_keypair_wallet(self.tmpdir, unlock=b'teste')
        builder.enable_address_index()
        builder.enable_tokens_index()

        self._config_builder(builder)

        artifacts = builder.build()
        self.reactor = artifacts.reactor
        self.pubsub = artifacts.pubsub
        self.manager = artifacts.manager
        self.tx_storage = artifacts.tx_storage
        self._settings = artifacts.settings

        assert artifacts.wallet is not None

        self.reactor.advance(time.time())

        self.tx_storage._manually_initialize()
        assert self.tx_storage.first_timestamp > 0

        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        block_parents = [tx.hash for tx in chain(self.genesis_blocks, self.genesis_txs)]
        output = TxOutput(200, P2PKH.create_output_script(BURN_ADDRESS))
        previous_timestamp = artifacts.settings.GENESIS_TX2_TIMESTAMP
        self.block = Block(timestamp=previous_timestamp + 1, weight=12, outputs=[output], parents=block_parents,
                           nonce=100781, storage=self.tx_storage)
        self.manager.cpu_mining_service.resolve(self.block)
        self.block.init_static_metadata_from_storage(self._settings, self.tx_storage)
        self.manager.verification_service.verify(self.block, self.get_verification_params(self.manager))
        self.block.get_metadata().validation = ValidationState.FULL

        tx_parents = [tx.hash for tx in self.genesis_txs]
        tx_input = TxInput(
            tx_id=self.genesis_blocks[0].hash, index=0,
            data=bytes.fromhex('46304402203470cb9818c9eb842b0c433b7e2b8aded0a51f5903e971649e870763d0266a'
                               'd2022049b48e09e718c4b66a0f3178ef92e4d60ee333d2d0e25af8868acf5acbb35aaa583'
                               '056301006072a8648ce3d020106052b8104000a034200042ce7b94cba00b654d4308f8840'
                               '7345cacb1f1032fb5ac80407b74d56ed82fb36467cb7048f79b90b1cf721de57e942c5748'
                               '620e78362cf2d908e9057ac235a63'))

        self.tx = Transaction(
            timestamp=previous_timestamp + 2, weight=10, nonce=932049, inputs=[tx_input], outputs=[output],
            tokens=[bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')],
            parents=tx_parents, storage=self.tx_storage)
        self.manager.cpu_mining_service.resolve(self.tx)
        self.tx.get_metadata().validation = ValidationState.FULL
        self.tx.init_static_metadata_from_storage(self._settings, self.tx_storage)

        # Disable weakref to test the internal methods. Otherwise, most methods return objects from weakref.
        self.tx_storage._disable_weakref()

        self.tx_storage.enable_lock()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_genesis_ref(self):
        # Enable weakref to this test only.
        self.tx_storage._enable_weakref()

        genesis_set = set(self.tx_storage.get_all_genesis())
        for tx in genesis_set:
            tx2 = self.tx_storage.get_transaction(tx.hash)
            self.assertTrue(tx is tx2)

    def test_genesis(self):
        self.assertEqual(1, len(self.genesis_blocks))
        self.assertEqual(2, len(self.genesis_txs))
        for tx in self.genesis:
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

        for tx in self.genesis:
            tx2 = self.tx_storage.get_transaction(tx.hash)
            self.assertEqual(tx, tx2)
            self.assertTrue(self.tx_storage.transaction_exists(tx.hash))

    def test_first_timestamp(self):
        self.assertEqual(self.tx_storage.first_timestamp, min(x.timestamp for x in self.genesis))

    def test_storage_basic(self):
        self.assertEqual(1, self.tx_storage.get_block_count())
        self.assertEqual(2, self.tx_storage.get_tx_count())
        self.assertEqual(3, self.tx_storage.get_vertices_count())
        self.assertEqual(self.genesis_blocks[0].hash, self.tx_storage.get_best_block_hash())
        self.assertEqual(
            {self.genesis_txs[0], self.genesis_txs[1]},
            set(self.tx_storage.iter_mempool_tips()),
        )

    def test_storage_basic_v2(self):
        self.assertEqual(1, self.tx_storage.get_block_count())
        self.assertEqual(2, self.tx_storage.get_tx_count())
        self.assertEqual(3, self.tx_storage.get_vertices_count())

        block_parent_hash = self.tx_storage.get_best_block_hash()
        self.assertEqual(block_parent_hash, self.genesis_blocks[0].hash)

        tx_parents_hash = self.manager.get_new_tx_parents()
        self.assertEqual(2, len(tx_parents_hash))
        self.assertEqual(set(tx_parents_hash), {self.genesis_txs[0].hash, self.genesis_txs[1].hash})

    def test_vertices_count(self):
        self.manager.daa.TEST_MODE = TestMode.TEST_ALL_WEIGHT

        blocks_count = 1
        txs_count = 2

        blocks = add_new_blocks(self.manager, 10, advance_clock=10)
        blocks_count += len(blocks)
        blocks = add_blocks_unlock_reward(self.manager)
        blocks_count += len(blocks)
        txs = add_new_transactions(self.manager, 5, advance_clock=5)
        txs_count += len(txs)
        blocks = add_new_blocks(self.manager, 10, advance_clock=10)
        blocks_count += len(blocks)
        txs = add_new_transactions(self.manager, 5, advance_clock=5)
        txs_count += len(txs)

        vertices_count = blocks_count + txs_count

        self.assertEqual(self.tx_storage.get_block_count(), blocks_count)
        self.assertEqual(self.tx_storage.get_tx_count(), txs_count)
        self.assertEqual(self.tx_storage.get_vertices_count(), vertices_count)

    def validate_save(self, obj):
        self.tx_storage.save_transaction(obj)
        self.tx_storage.indexes.add_to_non_critical_indexes(obj)

        loaded_obj1 = self.tx_storage.get_transaction(obj.hash)

        self.assertTrue(self.tx_storage.transaction_exists(obj.hash))

        self.assertEqual(obj, loaded_obj1)
        self.assertEqual(len(obj.get_funds_struct()), len(loaded_obj1.get_funds_struct()))
        self.assertEqual(bytes(obj), bytes(loaded_obj1))
        self.assertEqual(obj.to_json(), loaded_obj1.to_json())
        self.assertEqual(obj.is_block, loaded_obj1.is_block)

        idx_elem = (obj.timestamp, obj.hash)

        # Testing add and remove from cache
        self.assertIn(idx_elem, self.tx_storage.indexes.sorted_all)
        if obj.is_block:
            self.assertIn(idx_elem, self.tx_storage.indexes.sorted_blocks)
            self.assertNotIn(idx_elem, self.tx_storage.indexes.sorted_txs)
        else:
            self.assertIn(idx_elem, self.tx_storage.indexes.sorted_txs)
            self.assertNotIn(idx_elem, self.tx_storage.indexes.sorted_blocks)

        self.tx_storage.indexes.del_from_critical_indexes(obj)
        self.tx_storage.indexes.del_from_non_critical_indexes(obj, remove_all=True)

        self.assertNotIn(idx_elem, self.tx_storage.indexes.sorted_all)
        self.assertNotIn(idx_elem, self.tx_storage.indexes.sorted_txs)
        self.assertNotIn(idx_elem, self.tx_storage.indexes.sorted_blocks)

        self.tx_storage.indexes.add_to_non_critical_indexes(obj)
        self.assertIn(idx_elem, self.tx_storage.indexes.sorted_all)
        if obj.is_block:
            self.assertIn(idx_elem, self.tx_storage.indexes.sorted_blocks)
            self.assertNotIn(idx_elem, self.tx_storage.indexes.sorted_txs)
        else:
            self.assertIn(idx_elem, self.tx_storage.indexes.sorted_txs)
            self.assertNotIn(idx_elem, self.tx_storage.indexes.sorted_blocks)

    def test_save_block(self):
        self.validate_save(self.block)

    def test_save_tx(self):
        self.validate_save(self.tx)

    def test_pre_save_validation_invalid_tx_1(self):
        self.tx.get_metadata().validation = ValidationState.BASIC
        with self.assertRaises(AssertionError):
            # XXX: avoid using validate_save because an exception could be raised for other reasons
            self.tx_storage.save_transaction(self.tx)

    def test_pre_save_validation_invalid_tx_2(self):
        self.tx.get_metadata().add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)
        with self.assertRaises(AssertionError):
            with self.tx_storage.allow_partially_validated_context():
                # XXX: avoid using validate_save because an exception could be raised for other reasons
                self.tx_storage.save_transaction(self.tx)

    def test_pre_save_validation_success(self):
        self.tx.get_metadata().validation = ValidationState.BASIC
        self.tx.get_metadata().add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)
        with self.tx_storage.allow_partially_validated_context():
            # XXX: it's good to use validate_save now since we don't expect any exceptions to be raised
            self.validate_save(self.tx)

    def test_allow_scope_get_all_transactions(self):
        self.tx.get_metadata().validation = ValidationState.BASIC
        self.tx.get_metadata().add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)
        with self.tx_storage.allow_partially_validated_context():
            self.tx_storage.save_transaction(self.tx)
        only_valid_txs = list(self.tx_storage.get_all_transactions())
        self.assertNotIn(self.tx, only_valid_txs)
        with self.tx_storage.allow_partially_validated_context():
            txs_that_may_be_partial = list(self.tx_storage.get_all_transactions())
            self.assertIn(self.tx, txs_that_may_be_partial)

    def test_allow_scope_topological_sort_dfs(self):
        self.tx.get_metadata().validation = ValidationState.BASIC
        self.tx.get_metadata().add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)
        with self.tx_storage.allow_partially_validated_context():
            self.tx_storage.save_transaction(self.tx)
        only_valid_txs = list(self.tx_storage._topological_sort_dfs())
        self.assertNotIn(self.tx, only_valid_txs)
        with self.tx_storage.allow_partially_validated_context():
            txs_that_may_be_partial = list(self.tx_storage._topological_sort_dfs())
            self.assertIn(self.tx, txs_that_may_be_partial)

    def test_allow_partially_validated_context(self):
        from hathor.transaction.storage.exceptions import TransactionNotInAllowedScopeError
        self.tx.get_metadata().validation = ValidationState.BASIC
        self.tx.get_metadata().add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())
        # should fail because it is out of the allowed scope
        with self.assertRaises(TransactionNotInAllowedScopeError):
            # XXX: avoid using validate_save because an exception could be raised for other reasons
            self.tx_storage.save_transaction(self.tx)
        # should succeed because a custom scope is being used
        with self.tx_storage.allow_partially_validated_context():
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertTrue(self.tx_storage.is_partially_validated_allowed())
            self.assertFalse(self.tx_storage.is_invalid_allowed())
            self.validate_save(self.tx)
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())
        # should fail because it is out of the allowed scope
        with self.assertRaises(TransactionNotInAllowedScopeError):
            self.tx_storage.get_transaction(self.tx.hash)
        # should return None since TransactionNotInAllowedScopeError inherits TransactionDoesNotExist
        self.assertIsNone(self.tx_storage.get_metadata(self.tx.hash))
        # should succeed because a custom scope is being used
        with self.tx_storage.allow_partially_validated_context():
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertTrue(self.tx_storage.is_partially_validated_allowed())
            self.assertFalse(self.tx_storage.is_invalid_allowed())
            self.tx_storage.get_transaction(self.tx.hash)
            self.assertIsNotNone(self.tx_storage.get_metadata(self.tx.hash))

    def test_allow_invalid_context(self):
        from hathor.transaction.storage.exceptions import TransactionNotInAllowedScopeError
        self.validate_save(self.tx)
        self.tx.get_metadata().validation = ValidationState.INVALID
        # XXX: should this apply to invalid too? note that we never save invalid transactions so using the
        #      PARTIALLY_VALIDATED_ID marker is artificial just for testing
        self.tx.get_metadata().add_voided_by(self._settings.PARTIALLY_VALIDATED_ID)
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())
        # should fail because it is out of the allowed scope
        with self.assertRaises(TransactionNotInAllowedScopeError):
            # XXX: avoid using validate_save because an exception could be raised for other reasons
            self.tx_storage.save_transaction(self.tx)
        # should succeed because a custom scope is being used
        with self.tx_storage.allow_invalid_context():
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertFalse(self.tx_storage.is_partially_validated_allowed())
            self.assertTrue(self.tx_storage.is_invalid_allowed())
            self.validate_save(self.tx)
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())
        # should fail because it is out of the allowed scope
        with self.assertRaises(TransactionNotInAllowedScopeError):
            self.tx_storage.get_transaction(self.tx.hash)
        # should return None since TransactionNotInAllowedScopeError inherits TransactionDoesNotExist
        self.assertIsNone(self.tx_storage.get_metadata(self.tx.hash))
        # should succeed because a custom scope is being used
        with self.tx_storage.allow_invalid_context():
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertFalse(self.tx_storage.is_partially_validated_allowed())
            self.assertTrue(self.tx_storage.is_invalid_allowed())
            self.tx_storage.get_transaction(self.tx.hash)
            self.assertIsNotNone(self.tx_storage.get_metadata(self.tx.hash))

    def test_allow_scope_context_composing(self):
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())
        with self.tx_storage.allow_invalid_context():
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertFalse(self.tx_storage.is_partially_validated_allowed())
            self.assertTrue(self.tx_storage.is_invalid_allowed())
            with self.tx_storage.allow_partially_validated_context():
                self.assertFalse(self.tx_storage.is_only_valid_allowed())
                self.assertTrue(self.tx_storage.is_partially_validated_allowed())
                self.assertTrue(self.tx_storage.is_invalid_allowed())
                with self.tx_storage.allow_only_valid_context():
                    self.assertTrue(self.tx_storage.is_only_valid_allowed())
                    self.assertFalse(self.tx_storage.is_partially_validated_allowed())
                    self.assertFalse(self.tx_storage.is_invalid_allowed())
                self.assertFalse(self.tx_storage.is_only_valid_allowed())
                self.assertTrue(self.tx_storage.is_partially_validated_allowed())
                self.assertTrue(self.tx_storage.is_invalid_allowed())
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertFalse(self.tx_storage.is_partially_validated_allowed())
            self.assertTrue(self.tx_storage.is_invalid_allowed())
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())

    def test_allow_scope_context_stacking(self):
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())
        with self.tx_storage.allow_partially_validated_context():
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertTrue(self.tx_storage.is_partially_validated_allowed())
            self.assertFalse(self.tx_storage.is_invalid_allowed())
            with self.tx_storage.allow_partially_validated_context():
                self.assertFalse(self.tx_storage.is_only_valid_allowed())
                self.assertTrue(self.tx_storage.is_partially_validated_allowed())
                self.assertFalse(self.tx_storage.is_invalid_allowed())
                with self.tx_storage.allow_partially_validated_context():
                    self.assertFalse(self.tx_storage.is_only_valid_allowed())
                    self.assertTrue(self.tx_storage.is_partially_validated_allowed())
                    self.assertFalse(self.tx_storage.is_invalid_allowed())
                self.assertFalse(self.tx_storage.is_only_valid_allowed())
                self.assertTrue(self.tx_storage.is_partially_validated_allowed())
                self.assertFalse(self.tx_storage.is_invalid_allowed())
            self.assertFalse(self.tx_storage.is_only_valid_allowed())
            self.assertTrue(self.tx_storage.is_partially_validated_allowed())
            self.assertFalse(self.tx_storage.is_invalid_allowed())
        self.assertTrue(self.tx_storage.is_only_valid_allowed())
        self.assertFalse(self.tx_storage.is_partially_validated_allowed())
        self.assertFalse(self.tx_storage.is_invalid_allowed())

    def test_save_token_creation_tx(self):
        tx = create_tokens(self.manager, propagate=False)
        tx.get_metadata().validation = ValidationState.FULL
        tx.init_static_metadata_from_storage(self._settings, self.tx_storage)
        self.validate_save(tx)

    def _validate_not_in_index(self, tx, index):
        tips = index.tips_index[self.tx.timestamp]
        self.assertNotIn(self.tx.hash, [x.data for x in tips])
        self.assertNotIn(self.tx.hash, index.tips_index.tx_last_interval)

        self.assertIsNone(index.txs_index.find_tx_index(tx))

    def _test_remove_tx_or_block(self, tx):
        self.validate_save(tx)

        self.tx_storage.remove_transaction(tx)
        with self.assertRaises(TransactionDoesNotExist):
            self.tx_storage.get_transaction(tx.hash)

        if hasattr(self.tx_storage, 'all_index'):
            self._validate_not_in_index(tx, self.tx_storage.all_index)

        if tx.is_block:
            if hasattr(self.tx_storage, 'block_index'):
                self._validate_not_in_index(tx, self.tx_storage.block_index)
        else:
            if hasattr(self.tx_storage, 'tx_index'):
                self._validate_not_in_index(tx, self.tx_storage.tx_index)

        # Check wallet index.
        addresses_index = self.tx_storage.indexes.addresses
        addresses = tx.get_related_addresses()
        for address in addresses:
            self.assertNotIn(tx.hash, addresses_index.get_from_address(address))

        # TODO Check self.tx_storage.tokens_index

        # Try to remove twice. It is supposed to do nothing.
        self.tx_storage.remove_transaction(tx)

    def test_remove_tx(self):
        self._test_remove_tx_or_block(self.tx)

    def test_remove_block(self):
        self._test_remove_tx_or_block(self.block)

    def test_shared_memory(self):
        # Enable weakref to this test only.
        self.tx_storage._enable_weakref()

        self.validate_save(self.block)
        self.validate_save(self.tx)

        for tx in [self.tx, self.block]:
            # just making sure, if it is genesis the test is wrong
            self.assertFalse(tx.is_genesis)

            # load transactions twice
            tx1 = self.tx_storage.get_transaction(tx.hash)
            tx2 = self.tx_storage.get_transaction(tx.hash)

            # naturally they should be equal, but this time so do the objects
            self.assertTrue(tx1 == tx2)
            self.assertTrue(tx1 is tx2)

            meta1 = tx1.get_metadata()
            meta2 = tx2.get_metadata()

            # and naturally the metadata too
            self.assertTrue(meta1 == meta2)
            self.assertTrue(meta1 is meta2)

    def test_get_wrong_tx(self):
        hex_error = bytes.fromhex('00001c5c0b69d13b05534c94a69b2c8272294e6b0c536660a3ac264820677024')
        with self.assertRaises(TransactionDoesNotExist):
            self.tx_storage.get_transaction(hex_error)

    def test_save_metadata(self):
        # Saving genesis metadata
        self.tx_storage.save_transaction(self.genesis_txs[0], only_metadata=True)

        tx = self.block
        # First we save to the storage
        self.tx_storage.save_transaction(tx)

        metadata = tx.get_metadata()
        metadata.spent_outputs[1].append(self.genesis_blocks[0].hash)

        self.tx_storage.save_transaction(tx, only_metadata=True)
        tx2 = self.tx_storage.get_transaction(tx.hash)
        metadata2 = tx2.get_metadata()
        self.assertEqual(metadata, metadata2)

        total = 0
        for tx in self.tx_storage.get_all_transactions():
            total += 1

        self.assertEqual(total, 4)

    def test_storage_new_blocks(self):
        tip_block = self.tx_storage.get_best_block_hash()
        self.assertEqual(tip_block, self.genesis_blocks[0].hash)

        block1 = self._add_new_block()
        tip_block = self.tx_storage.get_best_block_hash()
        self.assertEqual(tip_block, block1.hash)

        block2 = self._add_new_block()
        tip_block = self.tx_storage.get_best_block_hash()
        self.assertEqual(tip_block, block2.hash)

        # Block3 has the same parents as block2.
        block3 = self._add_new_block(parents=block2.parents)
        self.assertEqual(block3.weight, block2.weight)
        meta2 = block2.get_metadata()
        meta3 = block3.get_metadata()
        self.assertEqual(meta2.score, meta3.score)
        tip_block = self.tx_storage.get_best_block_hash()
        self.assertEqual(tip_block, min(block2.hash, block3.hash))

        # Re-generate caches to test topological sort.
        self.tx_storage._manually_initialize()
        tip_block = self.tx_storage.get_best_block_hash()
        self.assertEqual(tip_block, min(block2.hash, block3.hash))

    def test_token_list(self):
        tx = self.tx
        self.validate_save(tx)
        # 2 token uids
        tx.tokens.append(bytes.fromhex('00001c5c0b69d13b05534c94a69b2c8272294e6b0c536660a3ac264820677024'))
        self.manager.cpu_mining_service.resolve(tx)
        tx._metadata.hash = tx.hash
        self.validate_save(tx)
        # no tokens
        tx.tokens = []
        self.manager.cpu_mining_service.resolve(tx)
        tx._metadata.hash = tx.hash
        self.validate_save(tx)

    def _add_new_block(self, parents=None):
        block = self.manager.generate_mining_block()
        block.data = b'Testing, testing, 1, 2, 3... testing, testing...'
        if parents is not None:
            block.parents = parents
        block.weight = 10
        self.assertTrue(self.manager.cpu_mining_service.resolve(block))
        self.manager.propagate_tx(block)
        self.reactor.advance(5)
        return block

    def test_topological_sort(self):
        self.manager.daa.TEST_MODE = TestMode.TEST_ALL_WEIGHT
        _total = 0
        blocks = add_new_blocks(self.manager, 1, advance_clock=1)
        _total += len(blocks)
        blocks = add_blocks_unlock_reward(self.manager)
        _total += len(blocks)
        add_new_transactions(self.manager, 1, advance_clock=1)

        total = 0
        for tx in self.tx_storage._topological_sort_dfs():
            total += 1

        # added blocks + genesis txs + added tx
        self.assertEqual(total, _total + 3 + 1)

    def test_get_best_block_weight(self):
        block = self._add_new_block()
        weight = self.tx_storage.get_weight_best_block()
        self.assertEqual(block.weight, weight)

    @inlineCallbacks
    def test_concurrent_access(self):
        self.tx_storage.save_transaction(self.tx)
        self.tx_storage._enable_weakref()

        def handle_error(err):
            self.fail('Error resolving concurrent access deferred. {}'.format(err))

        deferreds = []
        for i in range(5):
            d = deferToThread(self.tx_storage.get_transaction, self.tx.hash)
            d.addErrback(handle_error)
            deferreds.append(d)

        self.reactor.advance(3)
        yield gatherResults(deferreds)
        self.tx_storage._disable_weakref()

    def test_key_value_attribute(self):
        attr = 'test'
        val = 'a'

        # Try to get a key that does not exist
        self.assertIsNone(self.tx_storage.get_value(attr))

        # Try to remove this key that does not exist
        self.tx_storage.remove_value(attr)

        # Add the key/value
        self.tx_storage.add_value(attr, val)

        # Get correct value
        self.assertEqual(self.tx_storage.get_value(attr), val)

        # Remove the key
        self.tx_storage.remove_value(attr)

        # Key should not exist again
        self.assertIsNone(self.tx_storage.get_value(attr))


class BaseCacheStorageTest(BaseTransactionStorageTest):
    def _test_remove_tx_or_block(self, tx):
        tx_hash = tx.hash
        super()._test_remove_tx_or_block(tx)
        # XXX: make sure it was removed from the internal storage
        self.assertFalse(self.tx_storage.transaction_exists(tx_hash))


class TransactionRocksDBStorageTest(BaseTransactionStorageTest):
    __test__ = True

    def _config_builder(self, builder: TestBuilder) -> None:
        pass

    def test_storage_new_blocks(self):
        self.tx_storage._always_use_topological_dfs = True
        super().test_storage_new_blocks()


class CacheRocksDBStorageTest(BaseCacheStorageTest):
    __test__ = True

    def _config_builder(self, builder: TestBuilder) -> None:
        builder.use_tx_storage_cache(capacity=5)
