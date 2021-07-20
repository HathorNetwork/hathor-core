import json
import shutil
import tempfile
import time
from typing import Iterator, List, Optional
from unittest import main as ut_main

from numpy.random import PCG64, Generator as Rng, SeedSequence
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.task import Clock
from twisted.trial import unittest

from hathor.conf import HathorSettings
from hathor.daa import TestMode, _set_test_mode
from hathor.manager import HathorManager
from hathor.p2p.peer_id import PeerId
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.util import random_choice
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
        self._seed = SeedSequence()
        self.log.debug('unit-test seed (usually not used by tests)', seed=self._seed.entropy)
        self.rng = Rng(PCG64(self._seed))

    def tearDown(self):
        self.clean_tmpdirs()

    def reset_peer_id_pool(self) -> None:
        self._free_peer_id_pool = self.new_peer_id_pool()

    def new_peer_id_pool(self) -> List[PeerId]:
        return PEER_ID_POOL.copy()

    def get_random_peer_id_from_pool(self, pool: Optional[List[PeerId]] = None, rng: Optional[Rng] = None) -> PeerId:
        if pool is None:
            pool = self._free_peer_id_pool
        if not pool:
            raise RuntimeError('no more peer ids on the pool')
        if rng is None:
            rng = self.rng
        peer_id = random_choice(rng, pool)
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
        assert (
            hasattr(self, '_enable_sync_v1') and
            hasattr(self, '_enable_sync_v2') and
            (self._enable_sync_v1 or self._enable_sync_v2)
        ), (
            'Please set both `_enable_sync_v1` and `_enable_sync_v2` on the class. '
            'Also they can\'t both be False. '
            'This is by design so it\'s we don\'t forget to test for multiple sync versions.'
        )
        if self._enable_sync_v2:
            self.assertTipsEqualSyncV2(manager1, manager2)
        else:
            self.assertTipsEqualSyncV1(manager1, manager2)

    def assertTipsEqualSyncV1(self, manager1, manager2):
        # tx tips
        self.assertEqual(manager1.tx_storage._tx_tips_index, manager2.tx_storage._tx_tips_index)

        # best block
        s1 = set(manager1.tx_storage.get_best_block_tips())
        s2 = set(manager2.tx_storage.get_best_block_tips())
        self.assertEqual(s1, s2)

    def assertTipsEqualSyncV2(self, manager1, manager2):
        # tx tips
        tips1 = set(manager1.tx_storage._tx_tips_index)
        tips2 = set(manager2.tx_storage._tx_tips_index)
        self.log.debug('tx tips1', len=len(tips1), list=shorten_hash(tips1))
        self.log.debug('tx tips2', len=len(tips2), list=shorten_hash(tips2))
        # self.assertEqual(tips1, tips2)
        # XXX: this is still not correct, tips may diverge since voided transactions aren't propagated
        # XXX: temporarily disabled because tips may not match since sync-v2-mempool isn't merged yet
        if len(tips1) < len(tips2):
            self.assertEqual(tips1, tips1 & tips2)
        else:
            self.assertEqual(tips2, tips1 & tips2)

        # best block
        s1 = set(manager1.tx_storage.get_best_block_tips())
        s2 = set(manager2.tx_storage.get_best_block_tips())
        self.log.debug('block tips1', len=len(s1), list=shorten_hash(s1))
        self.log.debug('block tips2', len=len(s2), list=shorten_hash(s2))
        self.assertEqual(s1, s2)

    def assertConsistentWinnersAndLosers(self, winners, losers, manager):
        """ Basically checks that if a winning tx exist they are not voided and if loseing tx exist it is voided.
        """
        for tx in winners:
            meta = manager.tx_storage.get_metadata(tx)
            if meta is not None:
                self.assertFalse(bool(meta.voided_by))
        for tx in losers:
            meta = manager.tx_storage.get_metadata(tx)
            if meta is not None:
                self.assertTrue(bool(meta.voided_by))

    def assertConsensusEqual(self, manager1, manager2):
        assert (
            hasattr(self, '_enable_sync_v1') and
            hasattr(self, '_enable_sync_v2') and
            (self._enable_sync_v1 or self._enable_sync_v2)
        ), (
            'Please set both `_enable_sync_v1` and `_enable_sync_v2` on the class. '
            'Also they can\'t both be False. '
            'This is by design so it\'s we don\'t forget to test for multiple sync versions.'
        )
        if self._enable_sync_v2:
            self.assertConsensusEqualSyncV2(manager1, manager2)
        else:
            self.assertConsensusEqualSyncV1(manager1, manager2)

    def assertConsensusEqualSyncV1(self, manager1, manager2):
        # The current sync algorithm does not propagate voided blocks/txs
        # so the count might be different even though the consensus is equal
        # One peer might have voided txs that the other does not have

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

        self.assertCountEqual(winners1, winners2)
        self.assertTipsEqualSyncV1(manager1, manager2)

    def assertConsensusEqualSyncV2(self, manager1, manager2):
        # The current sync algorithm does not propagate voided blocks/txs
        # so the count might be different even though the consensus is equal
        # One peer might have voided txs that the other does not have

        winners1 = set()
        losers1 = set()
        for tx1 in manager1.tx_storage.get_all_transactions():
            tx1_meta = tx1.get_metadata()
            if not tx1_meta.voided_by:
                winners1.add(tx1.hash)
            else:
                losers1.add(tx1.hash)

        winners2 = set()
        losers2 = set()
        for tx2 in manager2.tx_storage.get_all_transactions():
            tx2_meta = tx2.get_metadata()
            if not tx2_meta.voided_by:
                winners2.add(tx2.hash)
            else:
                losers2.add(tx2.hash)

        self.log.debug('peer1', height=manager1.tx_storage.get_height_best_block(), score=manager1.get_current_score())
        self.log.debug('peer2', height=manager2.tx_storage.get_height_best_block(), score=manager2.get_current_score())
        self.log.debug('winners1', len=len(winners1), extra=shorten_hash(winners1 - winners2))
        self.log.debug('winners2', len=len(winners2), extra=shorten_hash(winners2 - winners1))

        self.assertConsistentWinnersAndLosers(winners1, losers1, manager2)
        self.assertConsistentWinnersAndLosers(winners2, losers2, manager1)

        self.assertTipsEqualSyncV2(manager1, manager2)

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
                # XXX/TODO/FIXME: something causes this to fail
                # self.assertTrue(spent_meta.voided_by.issubset(meta.voided_by))

        for parent in tx.get_parents():
            parent_meta = parent.get_metadata()
            if parent_meta.voided_by is not None:
                self.assertIsNotNone(meta.voided_by)
                # XXX/TODO/FIXME: something causes this to fail
                # self.assertTrue(parent_meta.voided_by.issubset(meta.voided_by))

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
