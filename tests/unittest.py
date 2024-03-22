import os
import secrets
import shutil
import tempfile
import time
from typing import Any, Callable, Collection, Iterable, Iterator, Optional
from unittest import main as ut_main

from structlog import get_logger
from twisted.trial import unittest

from hathor.builder import BuildArtifacts, Builder
from hathor.checkpoint import Checkpoint
from hathor.conf import HathorSettings
from hathor.conf.get_settings import get_global_settings
from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.event import EventManager
from hathor.event.storage import EventStorage
from hathor.manager import HathorManager
from hathor.p2p.peer_id import PeerId
from hathor.p2p.sync_v1.agent import NodeSyncTimestamp
from hathor.p2p.sync_v2.agent import NodeBlockSync
from hathor.p2p.sync_version import SyncVersion
from hathor.pubsub import PubSubManager
from hathor.reactor import ReactorProtocol as Reactor, get_global_reactor
from hathor.simulator.clock import MemoryReactorHeapClock
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.types import VertexId
from hathor.util import Random, not_none
from hathor.wallet import BaseWallet, HDWallet, Wallet
from tests.test_memory_reactor_clock import TestMemoryReactorClock

logger = get_logger()
main = ut_main
settings = HathorSettings()
USE_MEMORY_STORAGE = os.environ.get('HATHOR_TEST_MEMORY_STORAGE', 'false').lower() == 'true'


def short_hashes(container: Collection[bytes]) -> Iterable[str]:
    return map(lambda hash_bytes: hash_bytes[-2:].hex(), container)


def _load_peer_id_pool(file_path: Optional[str] = None) -> Iterator[PeerId]:
    import json

    if file_path is None:
        file_path = _get_default_peer_id_pool_filepath()

    with open(file_path) as peer_id_pool_file:
        peer_id_pool_dict = json.load(peer_id_pool_file)
        for peer_id_dict in peer_id_pool_dict:
            yield PeerId.create_from_json(peer_id_dict)


def _get_default_peer_id_pool_filepath() -> str:
    this_file_path = os.path.dirname(__file__)
    file_name = 'peer_id_pool.json'
    file_path = os.path.join(this_file_path, file_name)

    return file_path


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


class TestBuilder(Builder):
    __test__ = False

    def __init__(self) -> None:
        super().__init__()
        self.set_network('testnet')

    def build(self) -> BuildArtifacts:
        artifacts = super().build()
        # We disable rate limiter by default for tests because most tests were designed
        # to run without rate limits. You can enable it in your unittest if you need.
        artifacts.manager.connections.disable_rate_limiter()
        return artifacts

    def _get_peer_id(self) -> PeerId:
        if self._peer_id is not None:
            return self._peer_id
        return PeerId()

    def _get_reactor(self) -> Reactor:
        if self._reactor:
            return self._reactor
        return MemoryReactorHeapClock()


class TestCase(unittest.TestCase):
    _enable_sync_v1: bool
    _enable_sync_v2: bool
    use_memory_storage: bool = USE_MEMORY_STORAGE
    seed_config: Optional[int] = None

    def setUp(self) -> None:
        self.tmpdirs: list[str] = []
        self.clock = TestMemoryReactorClock()
        self.clock.advance(time.time())
        self.log = logger.new()
        self.reset_peer_id_pool()
        self.seed = secrets.randbits(64) if self.seed_config is None else self.seed_config
        self.log.info('set seed', seed=self.seed)
        self.rng = Random(self.seed)
        self._pending_cleanups: list[Callable[..., Any]] = []
        self._settings = get_global_settings()

    def tearDown(self) -> None:
        self.clean_tmpdirs()
        for fn in self._pending_cleanups:
            fn()

    def reset_peer_id_pool(self) -> None:
        self._free_peer_id_pool = self.new_peer_id_pool()

    def new_peer_id_pool(self) -> list[PeerId]:
        return PEER_ID_POOL.copy()

    def get_random_peer_id_from_pool(self, pool: Optional[list[PeerId]] = None,
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

    def mkdtemp(self) -> str:
        tmpdir = tempfile.mkdtemp()
        self.tmpdirs.append(tmpdir)
        return tmpdir

    def _create_test_wallet(self, unlocked: bool = False) -> Wallet:
        """ Generate a Wallet with a number of keypairs for testing
            :rtype: Wallet
        """
        tmpdir = self.mkdtemp()

        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'MYPASS')
        wallet.generate_keys(count=20)
        if not unlocked:
            wallet.lock()
        return wallet

    def get_builder(self, network: str) -> TestBuilder:
        builder = TestBuilder()
        builder.set_rng(self.rng) \
            .set_reactor(self.clock) \
            .set_network(network)
        return builder

    def create_peer_from_builder(self, builder: Builder, start_manager: bool = True) -> HathorManager:
        artifacts = builder.build()
        manager = artifacts.manager

        if artifacts.rocksdb_storage:
            self._pending_cleanups.append(artifacts.rocksdb_storage.close)

        # manager.avg_time_between_blocks = 0.0001  # FIXME: This property is not defined. Fix this.

        if start_manager:
            manager.start()
            self.clock.run()
            self.clock.advance(5)

        return manager

    def create_peer(  # type: ignore[no-untyped-def]
        self,
        network: str,
        peer_id: PeerId | None = None,
        wallet: BaseWallet | None = None,
        tx_storage: TransactionStorage | None = None,
        unlock_wallet: bool = True,
        wallet_index: bool = False,
        capabilities: list[str] | None = None,
        full_verification: bool = True,
        enable_sync_v1: bool | None = None,
        enable_sync_v2: bool | None = None,
        checkpoints: list[Checkpoint] | None = None,
        utxo_index: bool = False,
        event_manager: EventManager | None = None,
        use_memory_index: bool | None = None,
        start_manager: bool = True,
        pubsub: PubSubManager | None = None,
        event_storage: EventStorage | None = None,
        enable_event_queue: bool | None = None,
        use_memory_storage: bool | None = None
    ):  # TODO: Add -> HathorManager here. It breaks the lint in a lot of places.
        enable_sync_v1, enable_sync_v2 = self._syncVersionFlags(enable_sync_v1, enable_sync_v2)

        builder = self.get_builder(network) \
            .set_full_verification(full_verification)

        if checkpoints is not None:
            builder.set_checkpoints(checkpoints)

        if pubsub:
            builder.set_pubsub(pubsub)

        if peer_id is None:
            peer_id = PeerId()
        builder.set_peer_id(peer_id)

        if not wallet:
            wallet = self._create_test_wallet()
            if unlock_wallet:
                assert isinstance(wallet, Wallet)
                wallet.unlock(b'MYPASS')
        builder.set_wallet(not_none(wallet))

        if event_storage:
            builder.set_event_storage(event_storage)

        if event_manager:
            builder.set_event_manager(event_manager)

        if enable_event_queue:
            builder.enable_event_queue()

        if tx_storage is not None:
            builder.set_tx_storage(tx_storage)

        if use_memory_storage or self.use_memory_storage:
            builder.use_memory()
        else:
            directory = tempfile.mkdtemp()
            self.tmpdirs.append(directory)
            builder.use_rocksdb(directory)

        if use_memory_index is True:
            builder.force_memory_index()

        if enable_sync_v1 is True:
            builder.enable_sync_v1()
        elif enable_sync_v1 is False:
            builder.disable_sync_v1()

        if enable_sync_v2 is True:
            builder.enable_sync_v2()
        elif enable_sync_v2 is False:
            builder.disable_sync_v2()

        if wallet_index:
            builder.enable_wallet_index()

        if utxo_index:
            builder.enable_utxo_index()

        daa = DifficultyAdjustmentAlgorithm(settings=self._settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder.set_daa(daa)
        manager = self.create_peer_from_builder(builder, start_manager=start_manager)

        # XXX: just making sure that tests set this up correctly
        assert manager.connections.is_sync_version_enabled(SyncVersion.V2) == enable_sync_v2
        assert manager.connections.is_sync_version_enabled(SyncVersion.V1_1) == enable_sync_v1

        return manager

    def run_to_completion(self) -> None:
        """ This will advance the test's clock until all calls scheduled are done.
        """
        for call in self.clock.getDelayedCalls():
            amount = call.getTime() - self.clock.seconds()
            self.clock.advance(amount)

    def assertIsTopological(self, tx_sequence: Iterator[BaseTransaction], message: Optional[str] = None,
                            *, initial: Optional[Iterator[bytes]] = None) -> None:
        """Will check if a given sequence is in topological order.

        An initial set can be optionally provided.
        """
        from hathor.transaction.genesis import get_all_genesis_hashes

        valid_deps = set(get_all_genesis_hashes(self._settings) if initial is None else initial)

        for tx in tx_sequence:
            assert tx.hash is not None
            for dep in tx.get_all_dependencies():
                self.assertIn(dep, valid_deps, message)
            valid_deps.add(tx.hash)

    def _syncVersionFlags(
        self,
        enable_sync_v1: bool | None = None,
        enable_sync_v2: bool | None = None
    ) -> tuple[bool, bool]:
        """Internal: use this to check and get the flags and optionally provide override values."""
        if enable_sync_v1 is None:
            assert hasattr(self, '_enable_sync_v1'), ('`_enable_sync_v1` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v1` by argument')
            enable_sync_v1 = self._enable_sync_v1
        if enable_sync_v2 is None:
            assert hasattr(self, '_enable_sync_v2'), ('`_enable_sync_v2` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v2` by argument')
            enable_sync_v2 = self._enable_sync_v2
        assert enable_sync_v1 or enable_sync_v2, 'enable at least one sync version'
        return enable_sync_v1, enable_sync_v2

    def assertTipsEqual(self, manager1: HathorManager, manager2: HathorManager) -> None:
        _, enable_sync_v2 = self._syncVersionFlags()
        if enable_sync_v2:
            self.assertTipsEqualSyncV2(manager1, manager2)
        else:
            self.assertTipsEqualSyncV1(manager1, manager2)

    def assertTipsNotEqual(self, manager1: HathorManager, manager2: HathorManager) -> None:
        s1 = self._get_all_tips_form_best_index(manager1)
        s2 = self._get_all_tips_form_best_index(manager2)
        self.assertNotEqual(s1, s2)

    def _get_all_tips_form_best_index(self, manager: HathorManager) -> set[bytes]:
        assert manager.tx_storage.indexes is not None
        if manager.tx_storage.indexes.all_tips is not None:
            return self._get_all_tips_from_syncv1_indexes(manager.tx_storage)
        else:
            return self._get_all_tips_from_syncv2_indexes(manager.tx_storage)

    def _get_all_tips_from_syncv1_indexes(self, tx_storage: TransactionStorage) -> set[bytes]:
        assert tx_storage.indexes is not None
        assert tx_storage.indexes.all_tips is not None
        intervals = tx_storage.indexes.all_tips[tx_storage.latest_timestamp]
        tips = set(i.data for i in intervals)
        return tips

    def _get_all_tips_from_syncv2_indexes(self, tx_storage: TransactionStorage) -> set[bytes]:
        assert tx_storage.indexes is not None
        assert tx_storage.indexes.mempool_tips is not None
        tx_tips = tx_storage.indexes.mempool_tips.get()
        block_tip = tx_storage.indexes.height.get_tip()
        return tx_tips | {block_tip}

    def assertTipsEqualSyncV1(self, manager1: HathorManager, manager2: HathorManager) -> None:
        # XXX: this is the original implementation of assertTipsEqual
        s1 = set(manager1.tx_storage.get_all_tips())
        s2 = set(manager2.tx_storage.get_all_tips())
        self.assertEqual(s1, s2)

        s1 = set(manager1.tx_storage.get_tx_tips())
        s2 = set(manager2.tx_storage.get_tx_tips())
        self.assertEqual(s1, s2)

    def assertTipsEqualSyncV2(
        self,
        manager1: HathorManager,
        manager2: HathorManager,
        *,
        strict_sync_v2_indexes: bool = True
    ) -> None:
        # tx tips
        if strict_sync_v2_indexes:
            tips1 = not_none(not_none(manager1.tx_storage.indexes).mempool_tips).get()
            tips2 = not_none(not_none(manager2.tx_storage.indexes).mempool_tips).get()
        else:
            tips1 = {tx.hash for tx in manager1.tx_storage.iter_mempool_tips_from_best_index()}
            tips2 = {tx.hash for tx in manager2.tx_storage.iter_mempool_tips_from_best_index()}
        self.log.debug('tx tips1', len=len(tips1), list=short_hashes(tips1))
        self.log.debug('tx tips2', len=len(tips2), list=short_hashes(tips2))
        self.assertEqual(tips1, tips2)

        # best block
        s1 = set(manager1.tx_storage.get_best_block_tips())
        s2 = set(manager2.tx_storage.get_best_block_tips())
        self.log.debug('block tips1', len=len(s1), list=short_hashes(s1))
        self.log.debug('block tips2', len=len(s2), list=short_hashes(s2))
        self.assertEqual(s1, s2)

        # best block (from height index)
        b1 = not_none(manager1.tx_storage.indexes).height.get_tip()
        b2 = not_none(manager2.tx_storage.indexes).height.get_tip()
        self.assertIn(b1, s2)
        self.assertIn(b2, s1)

    def assertConsensusEqual(self, manager1: HathorManager, manager2: HathorManager) -> None:
        _, enable_sync_v2 = self._syncVersionFlags()
        if enable_sync_v2:
            self.assertConsensusEqualSyncV2(manager1, manager2)
        else:
            self.assertConsensusEqualSyncV1(manager1, manager2)

    def assertConsensusEqualSyncV1(self, manager1: HathorManager, manager2: HathorManager) -> None:
        self.assertEqual(manager1.tx_storage.get_vertices_count(), manager2.tx_storage.get_vertices_count())
        for tx1 in manager1.tx_storage.get_all_transactions():
            tx2 = manager2.tx_storage.get_transaction(tx1.hash)
            tx1_meta = tx1.get_metadata()
            tx2_meta = tx2.get_metadata()
            # conflict_with's type is Optional[list[bytes]], so we convert to a set because order does not matter.
            self.assertEqual(set(tx1_meta.conflict_with or []), set(tx2_meta.conflict_with or []))
            # Soft verification
            if tx1_meta.voided_by is None:
                # If tx1 is not voided, then tx2 must be not voided.
                self.assertIsNone(tx2_meta.voided_by)
            else:
                # If tx1 is voided, then tx2 must be voided.
                assert tx1_meta.voided_by is not None
                assert tx2_meta.voided_by is not None
                self.assertGreaterEqual(len(tx1_meta.voided_by), 1)
                self.assertGreaterEqual(len(tx2_meta.voided_by), 1)
            # Hard verification
            # self.assertEqual(tx1_meta.voided_by, tx2_meta.voided_by)

    def assertConsensusEqualSyncV2(
        self,
        manager1: HathorManager,
        manager2: HathorManager,
        *,
        strict_sync_v2_indexes: bool = True
    ) -> None:
        # The current sync algorithm does not propagate voided blocks/txs
        # so the count might be different even though the consensus is equal
        # One peer might have voided txs that the other does not have

        # to start off, both nodes must have the same tips
        self.assertTipsEqualSyncV2(manager1, manager2, strict_sync_v2_indexes=strict_sync_v2_indexes)

        # the following is specific to sync-v2

        # helper function:
        def get_all_executed_or_voided(
            tx_storage: TransactionStorage
        ) -> tuple[set[VertexId], set[VertexId], set[VertexId]]:
            """Get all txs separated into three sets: executed, voided, partial"""
            tx_executed = set()
            tx_voided = set()
            tx_partial = set()
            for tx in tx_storage.get_all_transactions():
                assert tx.hash is not None
                tx_meta = tx.get_metadata()
                if not tx_meta.validation.is_fully_connected():
                    tx_partial.add(tx.hash)
                elif not tx_meta.voided_by:
                    tx_executed.add(tx.hash)
                else:
                    tx_voided.add(tx.hash)
            return tx_executed, tx_voided, tx_partial

        # extract all the transactions from each node, split into three sets
        tx_executed1, tx_voided1, tx_partial1 = get_all_executed_or_voided(manager1.tx_storage)
        tx_executed2, tx_voided2, tx_partial2 = get_all_executed_or_voided(manager2.tx_storage)

        # both must have the exact same executed set
        self.assertEqual(tx_executed1, tx_executed2)

        # XXX: the rest actually doesn't matter
        self.log.debug('node1 rest', len_voided=len(tx_voided1), len_partial=len(tx_partial1))
        self.log.debug('node2 rest', len_voided=len(tx_voided2), len_partial=len(tx_partial2))

    def assertConsensusValid(self, manager: HathorManager) -> None:
        for tx in manager.tx_storage.get_all_transactions():
            if tx.is_block:
                assert isinstance(tx, Block)
                self.assertBlockConsensusValid(tx)
            else:
                assert isinstance(tx, Transaction)
                self.assertTransactionConsensusValid(tx)

    def assertBlockConsensusValid(self, block: Block) -> None:
        self.assertTrue(block.is_block)
        if not block.parents:
            # Genesis
            return
        meta = block.get_metadata()
        if meta.voided_by is None:
            parent = block.get_block_parent()
            parent_meta = parent.get_metadata()
            self.assertIsNone(parent_meta.voided_by)

    def assertTransactionConsensusValid(self, tx: Transaction) -> None:
        assert tx.storage is not None
        self.assertFalse(tx.is_block)
        meta = tx.get_metadata()
        if meta.voided_by and tx.hash in meta.voided_by:
            # If a transaction voids itself, then it must have at
            # least one conflict.
            self.assertTrue(meta.conflict_with)

        is_tx_executed = bool(not meta.voided_by)
        for h in meta.conflict_with or []:
            tx2 = tx.storage.get_transaction(h)
            meta2 = tx2.get_metadata()
            is_tx2_executed = bool(not meta2.voided_by)
            self.assertFalse(is_tx_executed and is_tx2_executed)

        for txin in tx.inputs:
            spent_tx = tx.get_spent_tx(txin)
            spent_meta = spent_tx.get_metadata()

            if spent_meta.voided_by is not None:
                assert meta.voided_by is not None
                self.assertTrue(spent_meta.voided_by)
                self.assertTrue(meta.voided_by)
                self.assertTrue(spent_meta.voided_by.issubset(meta.voided_by))

        for parent in tx.get_parents():
            parent_meta = parent.get_metadata()
            if parent_meta.voided_by is not None:
                assert meta.voided_by is not None
                self.assertTrue(parent_meta.voided_by)
                self.assertTrue(meta.voided_by)
                self.assertTrue(parent_meta.voided_by.issubset(meta.voided_by))

    def assertSyncedProgress(self, node_sync: NodeSyncTimestamp | NodeBlockSync) -> None:
        """Check "synced" status of p2p-manager, uses self._enable_sync_vX to choose which check to run."""
        enable_sync_v1, enable_sync_v2 = self._syncVersionFlags()
        if enable_sync_v2:
            assert isinstance(node_sync, NodeBlockSync)
            self.assertV2SyncedProgress(node_sync)
        elif enable_sync_v1:
            assert isinstance(node_sync, NodeSyncTimestamp)
            self.assertV1SyncedProgress(node_sync)

    def assertV1SyncedProgress(self, node_sync: NodeSyncTimestamp) -> None:
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)

    def assertV2SyncedProgress(self, node_sync: NodeBlockSync) -> None:
        self.assertEqual(node_sync.synced_block, node_sync.peer_best_block)

    def clean_tmpdirs(self) -> None:
        for tmpdir in self.tmpdirs:
            shutil.rmtree(tmpdir)

    def clean_pending(self, required_to_quiesce: bool = True) -> None:
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
        reactor = get_global_reactor()
        pending = reactor.getDelayedCalls()
        active = bool(pending)
        for p in pending:
            if p.active():
                p.cancel()
            else:
                print('WEIRDNESS! pending timed call not active!')
        if required_to_quiesce and active:
            self.fail('Reactor was still active when it was required to be quiescent.')

    def get_wallet(self) -> HDWallet:
        words = ('bind daring above film health blush during tiny neck slight clown salmon '
                 'wine brown good setup later omit jaguar tourist rescue flip pet salute')

        hd = HDWallet(words=words)
        hd._manually_initialize()
        return hd

    def get_address(self, index: int) -> Optional[str]:
        """ Generate a fixed HD Wallet and return an address
        """
        hd = self.get_wallet()

        if index >= hd.gap_limit:
            return None

        return list(hd.keys.keys())[index]
