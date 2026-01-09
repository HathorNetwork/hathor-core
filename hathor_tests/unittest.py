import base64
import os
import re
import secrets
import shutil
import tempfile
import time
from contextlib import contextmanager
from typing import Any, Callable, Collection, Iterable, Iterator, Optional
from unittest import main as ut_main
from unittest.mock import Mock

from structlog import get_logger
from twisted.trial import unittest

from hathor.builder import BuildArtifacts, Builder
from hathor.checkpoint import Checkpoint
from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.event import EventManager
from hathor.event.storage import EventStorage
from hathor.manager import HathorManager
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.sync_v2.agent import NodeBlockSync
from hathor.pubsub import PubSubManager
from hathor.reactor import ReactorProtocol as Reactor, get_global_reactor
from hathor.simulator.clock import MemoryReactorHeapClock
from hathor.storage import RocksDBStorage
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.types import VertexId
from hathor.util import Random, initialize_hd_wallet, not_none
from hathor.verification.verification_params import VerificationParams
from hathor.wallet import BaseWallet, Wallet
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock
from hathor_tests.utils import DEFAULT_WORDS

logger = get_logger()
main = ut_main


def short_hashes(container: Collection[bytes]) -> Iterable[str]:
    return map(lambda hash_bytes: hash_bytes[-2:].hex(), container)


def _load_peer_pool(file_path: Optional[str] = None) -> Iterator[PrivatePeer]:
    import json

    if file_path is None:
        file_path = _get_default_peer_id_pool_filepath()

    with open(file_path) as peer_id_pool_file:
        peer_id_pool_dict = json.load(peer_id_pool_file)
        for peer_id_dict in peer_id_pool_dict:
            yield PrivatePeer.create_from_json(peer_id_dict)


def _get_default_peer_id_pool_filepath() -> str:
    this_file_path = os.path.dirname(__file__)
    file_name = 'peer_id_pool.json'
    file_path = os.path.join(this_file_path, file_name)

    return file_path


PEER_ID_POOL = list(_load_peer_pool())

OCB_TEST_PRIVKEY: bytes = base64.b64decode(
    'MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCIdovnmKjK3KU'
    'c61YGgja0AgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQl2CJT4'
    'I2IUzRNoU9hyOWEwSBkLznN9Nunel+kK0FXpk//z0ZAnIyVacfHklCxFGyO'
    'j1VSjor0CHzH2Gmblvr+m7lCmRmqSVAwJpplqQYdBUF6sR9djHLY6svPY0o'
    '//dqQ/xM7QiY2FHlb3JQCTu7DaMflqPcJXlRXAFyoACnmj4/lUJWgrcWala'
    'rCSI+8rIillg3AU8/2gfoB1BxulVIIG35SQ=='
)
OCB_TEST_PASSWORD: bytes = b'OCBtestPW'


class TestBuilder(Builder):
    __test__ = False

    def __init__(self, settings: HathorSettings | None = None) -> None:
        super().__init__()
        # default builder has sync-v2 enabled for tests
        self.enable_sync_v2()
        self.set_settings(settings or get_global_settings())

    def build(self) -> BuildArtifacts:
        artifacts = super().build()
        # We disable rate limiter by default for tests because most tests were designed
        # to run without rate limits. You can enable it in your unittest if you need.
        artifacts.manager.connections.disable_rate_limiter()
        return artifacts

    def _get_peer(self) -> PrivatePeer:
        if self._peer is not None:
            return self._peer
        return PrivatePeer.auto_generated()

    def _get_reactor(self) -> Reactor:
        if self._reactor is None:
            self._reactor = MemoryReactorHeapClock()
        return self._reactor


class TestCase(unittest.TestCase):
    seed_config: Optional[int] = None

    def setUp(self) -> None:
        self.tmpdirs: list[str] = []
        self.clock = TestMemoryReactorClock()
        self.clock.advance(time.time())
        self.reactor = self.clock
        self.log = logger.new()
        self.reset_peer_pool()
        self.seed = secrets.randbits(64) if self.seed_config is None else self.seed_config
        self.log.info('set seed', seed=self.seed)
        self.rng = Random(self.seed)
        self._pending_cleanups: list[Callable[..., Any]] = []
        self._settings = get_global_settings()

    def tearDown(self) -> None:
        self.clean_tmpdirs()
        for fn in self._pending_cleanups:
            fn()

    def reset_peer_pool(self) -> None:
        self._free_peer_pool = self.new_peer_pool()

    def new_peer_pool(self) -> list[PrivatePeer]:
        return PEER_ID_POOL.copy()

    def get_random_peer_from_pool(
        self,
        pool: Optional[list[PrivatePeer]] = None,
        rng: Optional[Random] = None,
    ) -> PrivatePeer:
        if pool is None:
            pool = self._free_peer_pool
        if not pool:
            raise RuntimeError('no more peer ids on the pool')
        if rng is None:
            rng = self.rng
        peer = self.rng.choice(pool)
        pool.remove(peer)
        return peer

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

    def get_builder(self, settings: HathorSettings | None = None) -> TestBuilder:
        builder = TestBuilder(settings)
        builder.set_rng(self.rng) \
            .set_reactor(self.clock)
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
        peer: PrivatePeer | None = None,
        wallet: BaseWallet | None = None,
        tx_storage: TransactionStorage | None = None,
        unlock_wallet: bool = True,
        wallet_index: bool = False,
        capabilities: list[str] | None = None,
        checkpoints: list[Checkpoint] | None = None,
        utxo_index: bool = False,
        event_manager: EventManager | None = None,
        start_manager: bool = True,
        pubsub: PubSubManager | None = None,
        event_storage: EventStorage | None = None,
        enable_event_queue: bool | None = None,
        enable_ipv6: bool = False,
        disable_ipv4: bool = False,
        nc_indexes: bool = False,
        nc_log_config: NCLogConfig | None = None,
        settings: HathorSettings | None = None,
    ):  # TODO: Add -> HathorManager here. It breaks the lint in a lot of places.

        settings = (settings or self._settings)._replace(NETWORK_NAME=network)
        builder = self.get_builder() \
            .set_settings(settings)

        if checkpoints is not None:
            builder.set_checkpoints(checkpoints)

        if pubsub:
            builder.set_pubsub(pubsub)

        if peer is None:
            peer = PrivatePeer.auto_generated()
        builder.set_peer(peer)

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

        if wallet_index:
            builder.enable_wallet_index()

        if utxo_index:
            builder.enable_utxo_index()

        if tx_storage is not None:
            builder.set_tx_storage(tx_storage)

        if capabilities is not None:
            builder.set_capabilities(capabilities)

        if enable_ipv6:
            builder.enable_ipv6()

        if disable_ipv4:
            builder.disable_ipv4()

        daa = DifficultyAdjustmentAlgorithm(settings=self._settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder.set_daa(daa)

        if nc_indexes:
            builder.enable_nc_indexes()

        if nc_log_config:
            builder.set_nc_log_config(nc_log_config)

        manager = self.create_peer_from_builder(builder, start_manager=start_manager)

        return manager

    def create_tx_storage(self, settings: HathorSettings | None = None) -> TransactionStorage:
        artifacts = self.get_builder(settings).build()
        return artifacts.tx_storage

    def create_rocksdb_storage(self, settings: HathorSettings | None = None) -> RocksDBStorage:
        artifacts = self.get_builder(settings).build()
        return not_none(artifacts.rocksdb_storage)

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
            for dep in tx.get_all_dependencies():
                self.assertIn(dep, valid_deps, message)
            valid_deps.add(tx.hash)

    def assertTipsEqual(self, manager1: HathorManager, manager2: HathorManager) -> None:
        self.assertTipsEqualSyncV2(manager1, manager2)

    def assertTipsNotEqual(self, manager1: HathorManager, manager2: HathorManager) -> None:
        """For tips to be equals the set of tx-tips + block-tip have to be equal.

        This method assert that something should not match, either the tx-tips or the block-tip.
        """
        tips1 = manager1.tx_storage.indexes.mempool_tips.get()
        tips1 |= {manager1.tx_storage.indexes.height.get_tip()}
        tips2 = manager2.tx_storage.indexes.mempool_tips.get()
        tips2 |= {manager2.tx_storage.indexes.height.get_tip()}
        self.assertNotEqual(tips1, tips2)

    def assertTipsEqualSyncV2(
        self,
        manager1: HathorManager,
        manager2: HathorManager,
        *,
        strict_sync_v2_indexes: bool = True
    ) -> None:
        # tx tips
        if strict_sync_v2_indexes:
            tips1 = manager1.tx_storage.indexes.mempool_tips.get()
            tips2 = manager2.tx_storage.indexes.mempool_tips.get()
        else:
            tips1 = {tx.hash for tx in manager1.tx_storage.iter_mempool_tips()}
            tips2 = {tx.hash for tx in manager2.tx_storage.iter_mempool_tips()}
        self.log.debug('tx tips1', len=len(tips1), list=short_hashes(tips1))
        self.log.debug('tx tips2', len=len(tips2), list=short_hashes(tips2))
        self.assertEqual(tips1, tips2)

        # best block
        s1 = manager1.tx_storage.get_best_block_hash()
        s2 = manager2.tx_storage.get_best_block_hash()
        self.log.debug('block tip1', block=s1.hex())
        self.log.debug('block tip2', block=s2.hex())
        self.assertEqual(s1, s2)

        # best block (from height index)
        b1 = manager1.tx_storage.indexes.height.get_tip()
        b2 = manager2.tx_storage.indexes.height.get_tip()
        self.assertIn(b1, s2)
        self.assertIn(b2, s1)

    def assertConsensusEqual(self, manager1: HathorManager, manager2: HathorManager) -> None:
        self.assertConsensusEqualSyncV2(manager1, manager2)

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

    def assertSyncedProgress(self, node_sync: NodeBlockSync) -> None:
        """Check "synced" status of p2p-manager, uses self._enable_sync_vX to choose which check to run."""
        self.assertV2SyncedProgress(node_sync)

    def assertV2SyncedProgress(self, node_sync: NodeBlockSync) -> None:
        self.assertEqual(node_sync.synced_block, node_sync.peer_best_block)

    @contextmanager
    def assertNCFail(self, class_name: str, pattern: str | re.Pattern[str] | None = None) -> Iterator[BaseException]:
        """Assert that a NCFail is raised and it has the expected class name and str(exc) format.
        """
        from hathor.nanocontracts.exception import NCFail

        with self.assertRaises(NCFail) as cm:
            yield cm

        self.assertEqual(cm.exception.__class__.__name__, class_name)

        if pattern is not None:
            actual = str(cm.exception)
            if isinstance(pattern, re.Pattern):
                assert pattern.match(actual)
            else:
                self.assertEqual(pattern, actual)

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

    def get_address(self, index: int) -> Optional[str]:
        """ Generate a fixed HD Wallet and return an address
        """
        hd = initialize_hd_wallet(DEFAULT_WORDS)

        if index >= hd.gap_limit:
            return None

        return list(hd.keys.keys())[index]

    @staticmethod
    def get_verification_params(manager: HathorManager | None = None) -> VerificationParams:
        best_block = manager.tx_storage.get_best_block() if manager else None
        return VerificationParams.default_for_mempool(best_block=best_block or Mock())
