import random
import shutil
import tempfile
import time

import numpy.random
from twisted.internet import reactor
from twisted.internet.task import Clock
from twisted.trial import unittest

from hathor.manager import HathorManager, TestMode
from hathor.p2p.peer_id import PeerId
from hathor.wallet import Wallet


class TestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdirs = []
        self.clock = Clock()
        self.clock.advance(time.time())
        # before patching genesis, validate the original ones are correct
        self._validate_real_genesis()
        self._patch_genesis_block()

    def _patch_genesis_block(self):
        """ Updates the genesis block so we can easily spend the outputs during tests. When we make any
        changes to tx structure that impacts the hash, we also must change it here (the nonce and hash).
        The steps for updating it are:
        1. use the genesis block (block = hathor.transaction.genesis.GENESIS[0])
        2. update the output script to use the one as bellow
        3. mine block again: block.start_mining(update_time=False)
        4. update hash: block.update_hash()
        5. replace block nonce and hash on this function with the new ones
        """
        import hathor.transaction.genesis
        from hathor.transaction import Block
        block = hathor.transaction.genesis.GENESIS[0]
        assert isinstance(block, Block)
        block.outputs[0].script = bytes.fromhex('76a914fd05059b6006249543b82f36876a17c73fd2267b88ac')
        block.resolve(update_time=False)
        block.nonce = 1438257
        block.update_hash()
        assert block.hash_hex == '00000087afe53259732782269fb62243ad52b669728394d492b1e84c259fb85c'

    def tearDown(self):
        self.clean_tmpdirs()

    def _validate_real_genesis(self):
        import hathor.transaction.genesis
        for tx in hathor.transaction.genesis.GENESIS:
            self.assertEqual(tx.hash, tx.calculate_hash())
            tx.verify_without_storage()

    def _create_test_wallet(self):
        """ Generate a Wallet with a number of keypairs for testing
            :rtype: Wallet
        """
        tmpdir = tempfile.mkdtemp(dir='/tmp/')
        self.tmpdirs.append(tmpdir)

        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'MYPASS')
        wallet.generate_keys(count=20)
        wallet.lock()
        return wallet

    def create_peer(self, network, peer_id=None, wallet=None, tx_storage=None, unlock_wallet=True, wallet_index=False):
        if peer_id is None:
            peer_id = PeerId()
        if not wallet:
            wallet = self._create_test_wallet()
            if unlock_wallet:
                wallet.unlock(b'MYPASS')
        manager = HathorManager(
            self.clock,
            peer_id=peer_id,
            network=network,
            wallet=wallet,
            tx_storage=tx_storage,
            wallet_index=wallet_index
        )
        manager.avg_time_between_blocks = 0.0001
        manager.test_mode = TestMode.TEST_ALL_WEIGHT
        manager.start()
        self.run_to_completion()
        return manager

    def run_to_completion(self):
        """ This will advance the test's clock until all calls scheduled are done.
        """
        for call in self.clock.getDelayedCalls():
            amount = call.getTime() - self.clock.seconds()
            self.clock.advance(amount)

    def set_random_seed(self, seed=None):
        if seed is None:
            seed = numpy.random.randint(2**32)
        self.random_seed = seed
        random.seed(self.random_seed)
        numpy.random.seed(self.random_seed)

    def assertTipsEqual(self, manager1, manager2):
        s1 = set(manager1.tx_storage.get_all_tips())
        s2 = set(manager2.tx_storage.get_all_tips())
        self.assertEqual(s1, s2)

        s1 = set(manager1.tx_storage.get_tx_tips())
        s2 = set(manager2.tx_storage.get_tx_tips())
        self.assertEqual(s1, s2)

    def assertTipsNotEqual(self, manager1, manager2):
        s1 = set(manager1.tx_storage.get_all_tips())
        s2 = set(manager2.tx_storage.get_all_tips())
        self.assertNotEqual(s1, s2)

    def assertConsensusEqual(self, manager1, manager2):
        self.assertEqual(manager1.tx_storage.get_count_tx_blocks(), manager2.tx_storage.get_count_tx_blocks())
        for tx1 in manager1.tx_storage.get_all_transactions():
            tx2 = manager2.tx_storage.get_transaction(tx1.hash)
            tx1_meta = tx1.get_metadata()
            tx2_meta = tx2.get_metadata()
            self.assertEqual(tx1_meta.conflict_with, tx2_meta.conflict_with)
            # Soft verification
            if tx1_meta.voided_by is None:
                # If tx1 is not voided, then tx2 must be not voided.
                self.assertIsNone(tx2_meta.voided_by)
            else:
                # If tx1 is voided, then tx2 must be voided.
                self.assertGreaterEqual(len(tx1_meta.voided_by), 1)
                self.assertGreaterEqual(len(tx2_meta.voided_by), 1)
            # Hard verification
            # self.assertEqual(tx1_meta.voided_by, tx2_meta.voided_by)

    def assertConsensusValid(self, manager):
        for tx in manager.tx_storage.get_all_transactions():
            if tx.is_block:
                self.assertBlockConsensusValid(tx)
            else:
                self.assertTransactionConsensusValid(tx)

    def assertBlockConsensusValid(self, block):
        self.assertTrue(block.is_block)
        if not block.parents:
            # Genesis
            return
        meta = block.get_metadata()
        if meta.voided_by is None:
            parent = block.get_block_parent()
            parent_meta = parent.get_metadata()
            self.assertIsNone(parent_meta.voided_by)

    def assertTransactionConsensusValid(self, tx):
        self.assertFalse(tx.is_block)
        meta = tx.get_metadata()
        if meta.voided_by and tx.hash in meta.voided_by:
            # If a transaction voids itself, then it must have at
            # least one conflict.
            self.assertTrue(meta.conflict_with)

        for txin in tx.inputs:
            spent_tx = tx.get_spent_tx(txin)
            spent_meta = spent_tx.get_metadata()

            if spent_meta.voided_by is not None:
                self.assertIsNotNone(meta.voided_by)
                self.assertTrue(spent_meta.voided_by.issubset(meta.voided_by))

        for parent in tx.get_parents():
            parent_meta = parent.get_metadata()
            if parent_meta.voided_by is not None:
                self.assertIsNotNone(meta.voided_by)
                self.assertTrue(parent_meta.voided_by.issubset(meta.voided_by))

    def clean_tmpdirs(self):
        for tmpdir in self.tmpdirs:
            shutil.rmtree(tmpdir)

    def clean_pending(self, required_to_quiesce=True):
        """
        This handy method cleans all pending tasks from the reactor.

        When writing a unit test, consider the following question:

            Is the code that you are testing required to release control once it
            has done its job, so that it is impossible for it to later come around
            (with a delayed reactor task) and do anything further?

        If so, then trial will usefully test that for you -- if the code under
        test leaves any pending tasks on the reactor then trial will fail it.

        On the other hand, some code is *not* required to release control -- some
        code is allowed to continuously maintain control by rescheduling reactor
        tasks in order to do ongoing work.  Trial will incorrectly require that
        code to clean up all its tasks from the reactor.

        Most people think that such code should be amended to have an optional
        "shutdown" operation that releases all control, but on the contrary it is
        good design for some code to *not* have a shutdown operation, but instead
        to have a "crash-only" design in which it recovers from crash on startup.

        If the code under test is of the "long-running" kind, which is *not*
        required to shutdown cleanly in order to pass tests, then you can simply
        call testutil.clean_pending() at the end of the unit test, and trial will
        be satisfied.

        Copy from: https://github.com/zooko/pyutil/blob/master/pyutil/testutil.py#L68
        """
        pending = reactor.getDelayedCalls()
        active = bool(pending)
        for p in pending:
            if p.active():
                p.cancel()
            else:
                print('WEIRDNESS! pending timed call not active!')
        if required_to_quiesce and active:
            self.fail('Reactor was still active when it was required to be quiescent.')

    def get_address(self, index: int) -> str:
        """ Generate a fixed HD Wallet and return an address
        """
        from hathor.wallet import HDWallet
        words = ('bind daring above film health blush during tiny neck slight clown salmon '
                 'wine brown good setup later omit jaguar tourist rescue flip pet salute')

        hd = HDWallet(words=words)
        hd._manually_initialize()

        if index >= hd.gap_limit:
            return None

        return list(hd.keys.keys())[index]
