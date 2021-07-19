import json
import shutil
import tempfile
import time
from typing import Iterator, List, Optional
from unittest import main as ut_main

from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.task import Clock
from twisted.trial import unittest

from hathor.conf import HathorSettings
from hathor.daa import TestMode, _set_test_mode
from hathor.manager import HathorManager
from hathor.p2p.peer_id import PeerId
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.util import Random
from hathor.wallet import Wallet

logger = get_logger()
main = ut_main
settings = HathorSettings()


def shorten_hash(container):
    container_type = type(container)
    return container_type(h[-2:].hex() for h in container)


def _load_peer_id_pool(file_path: str = 'tests/peer_id_pool.json') -> Iterator[PeerId]:
    with open(file_path) as peer_id_pool_file:
        peer_id_pool_dict = json.load(peer_id_pool_file)
        for peer_id_dict in peer_id_pool_dict:
            yield PeerId.create_from_json(peer_id_dict)


PEER_ID_POOL = list(_load_peer_id_pool())

# XXX: Sync*Params classes should be inherited before the TestCase class when a sync version is needed


class SyncV1Params:
    _enable_sync_v1 = True
    _enable_sync_v2 = False


class SyncV2Params:
    _enable_sync_v1 = False
    _enable_sync_v2 = True


class SyncBridgeParams:
    _enable_sync_v1 = True
    _enable_sync_v2 = True


class TestCase(unittest.TestCase):
    _enable_sync_v1: bool
    _enable_sync_v2: bool

    def setUp(self):
        _set_test_mode(TestMode.TEST_ALL_WEIGHT)
        self.tmpdirs = []
        self.clock = Clock()
        self.clock.advance(time.time())
        self.log = logger.new()
        self.reset_peer_id_pool()
        self.rng = Random()

    def tearDown(self):
        self.clean_tmpdirs()

    def reset_peer_id_pool(self) -> None:
        self._free_peer_id_pool = self.new_peer_id_pool()

    def new_peer_id_pool(self) -> List[PeerId]:
        return PEER_ID_POOL.copy()

    def get_random_peer_id_from_pool(self, pool: Optional[List[PeerId]] = None,
                                     rng: Optional[Random] = None) -> PeerId:
        if pool is None:
            pool = self._free_peer_id_pool
        if not pool:
            raise RuntimeError('no more peer ids on the pool')
        if rng is None:
            rng = self.rng
        peer_id = self.rng.choice(pool)
        pool.remove(peer_id)
        return peer_id

    def _create_test_wallet(self):
        """ Generate a Wallet with a number of keypairs for testing
            :rtype: Wallet
        """
        tmpdir = tempfile.mkdtemp()
        self.tmpdirs.append(tmpdir)

        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'MYPASS')
        wallet.generate_keys(count=20)
        wallet.lock()
        return wallet

    def create_peer(self, network, peer_id=None, wallet=None, tx_storage=None, unlock_wallet=True, wallet_index=False,
                    capabilities=None, full_verification=True, enable_sync_v1=None, enable_sync_v2=None):
        if enable_sync_v1 is None:
            assert hasattr(self, '_enable_sync_v1'), ('`_enable_sync_v1` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v1` by argument')
            enable_sync_v1 = self._enable_sync_v1
        if enable_sync_v2 is None:
            assert hasattr(self, '_enable_sync_v2'), ('`_enable_sync_v2` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v2` by argument')
            enable_sync_v2 = self._enable_sync_v2
        assert enable_sync_v1 or enable_sync_v2, 'enable at least one sync version'

        if peer_id is None:
            peer_id = PeerId()
        if not wallet:
            wallet = self._create_test_wallet()
            if unlock_wallet:
                wallet.unlock(b'MYPASS')
        if tx_storage is None:
            tx_storage = TransactionMemoryStorage()
        manager = HathorManager(
            self.clock,
            peer_id=peer_id,
            network=network,
            wallet=wallet,
            tx_storage=tx_storage,
            wallet_index=wallet_index,
            capabilities=capabilities,
            rng=self.rng,
            enable_sync_v1=enable_sync_v1,
            enable_sync_v2=enable_sync_v2,
        )

        # XXX: just making sure that tests set this up correctly
        if enable_sync_v2:
            assert settings.CAPABILITY_SYNC_V2 in manager.capabilities
        else:
            assert settings.CAPABILITY_SYNC_V2 not in manager.capabilities

        manager.avg_time_between_blocks = 0.0001
        manager._full_verification = full_verification
        manager.start()
        self.run_to_completion()
        return manager

    def run_to_completion(self):
        """ This will advance the test's clock until all calls scheduled are done.
        """
        for call in self.clock.getDelayedCalls():
            amount = call.getTime() - self.clock.seconds()
            self.clock.advance(amount)

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

    def get_address(self, index: int) -> Optional[str]:
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
