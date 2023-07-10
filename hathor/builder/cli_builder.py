# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import getpass
import json
import os
import platform
import sys
from typing import Any, Optional

from structlog import get_logger

from hathor.cli.run_node import RunNodeArgs
from hathor.consensus import ConsensusAlgorithm
from hathor.event import EventManager
from hathor.exception import BuilderError
from hathor.indexes import IndexesManager, MemoryIndexesManager, RocksDBIndexesManager
from hathor.manager import HathorManager
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer_id import PeerId
from hathor.p2p.utils import discover_hostname
from hathor.pubsub import PubSubManager
from hathor.stratum import StratumFactory
from hathor.util import Random, Reactor
from hathor.wallet import BaseWallet, HDWallet, Wallet

logger = get_logger()


class CliBuilder:
    """CliBuilder builds the core objects from args.

    TODO Refactor to use Builder. It could even be ported to a Builder.from_args classmethod.
    """
    def __init__(self, args: RunNodeArgs) -> None:
        self.log = logger.new()
        self._args = args

    def check_or_raise(self, condition: bool, message: str) -> None:
        """Will exit printing `message` if `condition` is False."""
        if not condition:
            raise BuilderError(message)

    def create_manager(self, reactor: Reactor) -> HathorManager:
        import hathor
        from hathor.conf import HathorSettings
        from hathor.conf.get_settings import get_settings_source
        from hathor.daa import TestMode, _set_test_mode
        from hathor.event.storage import EventMemoryStorage, EventRocksDBStorage, EventStorage
        from hathor.event.websocket.factory import EventWebsocketFactory
        from hathor.p2p.netfilter.utils import add_peer_id_blacklist
        from hathor.p2p.peer_discovery import BootstrapPeerDiscovery, DNSPeerDiscovery
        from hathor.storage import RocksDBStorage
        from hathor.transaction import genesis
        from hathor.transaction.storage import (
            TransactionCacheStorage,
            TransactionMemoryStorage,
            TransactionRocksDBStorage,
            TransactionStorage,
        )
        from hathor.util import get_environment_info

        settings = HathorSettings()

        # only used for logging its location
        settings_source = get_settings_source()

        self.log = logger.new()
        self.reactor = reactor

        peer_id = self.create_peer_id()

        python = f'{platform.python_version()}-{platform.python_implementation()}'

        self.log.info(
            'hathor-core v{hathor}',
            hathor=hathor.__version__,
            pid=os.getpid(),
            genesis=genesis.GENESIS_HASH.hex()[:7],
            my_peer_id=str(peer_id.id),
            python=python,
            platform=platform.platform(),
            settings=settings_source,
        )

        tx_storage: TransactionStorage
        event_storage: EventStorage
        indexes: IndexesManager
        self.rocksdb_storage: Optional[RocksDBStorage] = None
        self.event_ws_factory: Optional[EventWebsocketFactory] = None

        if self._args.memory_storage:
            self.check_or_raise(not self._args.data, '--data should not be used with --memory-storage')
            # if using MemoryStorage, no need to have cache
            indexes = MemoryIndexesManager()
            tx_storage = TransactionMemoryStorage(indexes)
            event_storage = EventMemoryStorage()
            self.check_or_raise(not self._args.x_rocksdb_indexes, 'RocksDB indexes require RocksDB data')
            self.log.info('with storage', storage_class=type(tx_storage).__name__)
        else:
            self.check_or_raise(bool(self._args.data), '--data is expected')
            assert self._args.data is not None
            if self._args.rocksdb_storage:
                self.log.warn('--rocksdb-storage is now implied, no need to specify it')
            cache_capacity = self._args.rocksdb_cache
            self.rocksdb_storage = RocksDBStorage(path=self._args.data, cache_capacity=cache_capacity)

            # Initialize indexes manager.
            if self._args.memory_indexes:
                indexes = MemoryIndexesManager()
            else:
                indexes = RocksDBIndexesManager(self.rocksdb_storage)

            kwargs = {}
            if not self._args.cache:
                # We should only pass indexes if cache is disabled. Otherwise,
                # only TransactionCacheStorage should have indexes.
                kwargs['indexes'] = indexes
            tx_storage = TransactionRocksDBStorage(self.rocksdb_storage, **kwargs)
            event_storage = EventRocksDBStorage(self.rocksdb_storage)

        self.log.info('with storage', storage_class=type(tx_storage).__name__, path=self._args.data)
        if self._args.cache:
            self.check_or_raise(not self._args.memory_storage, '--cache should not be used with --memory-storage')
            tx_storage = TransactionCacheStorage(tx_storage, reactor, indexes=indexes)
            if self._args.cache_size:
                tx_storage.capacity = self._args.cache_size
            if self._args.cache_interval:
                tx_storage.interval = self._args.cache_interval
            self.log.info('with cache', capacity=tx_storage.capacity, interval=tx_storage.interval)
        self.tx_storage = tx_storage
        self.log.info('with indexes', indexes_class=type(tx_storage.indexes).__name__)

        self.wallet = None
        if self._args.wallet:
            self.wallet = self.create_wallet()
            self.log.info('with wallet', wallet=self.wallet, path=self._args.data)

        hostname = self.get_hostname()
        network = settings.NETWORK_NAME
        enable_sync_v1 = self._args.x_enable_legacy_sync_v1_0
        enable_sync_v1_1 = not self._args.x_sync_v2_only
        enable_sync_v2 = self._args.x_sync_v2_only or self._args.x_sync_bridge

        pubsub = PubSubManager(reactor)

        if self._args.x_enable_event_queue:
            self.event_ws_factory = EventWebsocketFactory(reactor, event_storage)

        event_manager = EventManager(
            event_storage=event_storage,
            event_ws_factory=self.event_ws_factory,
            pubsub=pubsub,
            reactor=reactor
        )

        if self._args.wallet_index and tx_storage.indexes is not None:
            self.log.debug('enable wallet indexes')
            self.enable_wallet_index(tx_storage.indexes, pubsub)

        if self._args.utxo_index and tx_storage.indexes is not None:
            self.log.debug('enable utxo index')
            tx_storage.indexes.enable_utxo_index()

        full_verification = False
        if self._args.x_full_verification:
            self.check_or_raise(
                not self._args.x_enable_event_queue,
                '--x-full-verification cannot be used with --x-enable-event-queue'
            )
            full_verification = True

        soft_voided_tx_ids = set(settings.SOFT_VOIDED_TX_IDS)
        consensus_algorithm = ConsensusAlgorithm(soft_voided_tx_ids, pubsub=pubsub)

        if self._args.x_enable_event_queue:
            self.log.info('--x-enable-event-queue flag provided. '
                          'The events detected by the full node will be stored and can be retrieved by clients')

        p2p_manager = ConnectionsManager(
            reactor,
            network=network,
            my_peer=peer_id,
            pubsub=pubsub,
            ssl=True,
            whitelist_only=False,
            rng=Random(),
            enable_sync_v1=enable_sync_v1,
            enable_sync_v1_1=enable_sync_v1_1,
            enable_sync_v2=enable_sync_v2,
        )

        self.manager = HathorManager(
            reactor,
            network=network,
            hostname=hostname,
            pubsub=pubsub,
            consensus_algorithm=consensus_algorithm,
            peer_id=peer_id,
            tx_storage=tx_storage,
            p2p_manager=p2p_manager,
            event_manager=event_manager,
            wallet=self.wallet,
            checkpoints=settings.CHECKPOINTS,
            environment_info=get_environment_info(args=str(self._args), peer_id=peer_id.id),
            full_verification=full_verification,
            enable_event_queue=self._args.x_enable_event_queue
        )

        p2p_manager.set_manager(self.manager)

        if self._args.stratum:
            stratum_factory = StratumFactory(self.manager)
            self.manager.stratum_factory = stratum_factory
            self.manager.metrics.stratum_factory = stratum_factory

        if self._args.data:
            self.manager.set_cmd_path(self._args.data)

        if self._args.allow_mining_without_peers:
            self.manager.allow_mining_without_peers()

        if self._args.x_localhost_only:
            self.manager.connections.localhost_only = True

        dns_hosts = []
        if settings.BOOTSTRAP_DNS:
            dns_hosts.extend(settings.BOOTSTRAP_DNS)

        if self._args.dns:
            dns_hosts.extend(self._args.dns)

        if dns_hosts:
            self.manager.add_peer_discovery(DNSPeerDiscovery(dns_hosts))

        if self._args.bootstrap:
            self.manager.add_peer_discovery(BootstrapPeerDiscovery(self._args.bootstrap))

        if self._args.test_mode_tx_weight:
            _set_test_mode(TestMode.TEST_TX_WEIGHT)
            if self.wallet:
                self.wallet.test_mode = True

        if self._args.x_rocksdb_indexes:
            self.log.warn('--x-rocksdb-indexes is now the default, no need to specify it')
            if self._args.memory_indexes:
                raise BuilderError('You cannot use --memory-indexes and --x-rocksdb-indexes.')

        if self._args.memory_indexes and self._args.memory_storage:
            self.log.warn('--memory-indexes is implied for memory storage or JSON storage')

        for description in self._args.listen:
            self.manager.add_listen_address(description)

        if self._args.peer_id_blacklist:
            self.log.info('with peer id blacklist', blacklist=self._args.peer_id_blacklist)
            add_peer_id_blacklist(self._args.peer_id_blacklist)

        return self.manager

    def enable_wallet_index(self, indexes: IndexesManager, pubsub: PubSubManager) -> None:
        self.log.debug('enable wallet indexes')
        indexes.enable_address_index(pubsub)
        indexes.enable_tokens_index()

    def get_hostname(self) -> Optional[str]:
        if self._args.hostname and self._args.auto_hostname:
            print('You cannot use --hostname and --auto-hostname together.')
            sys.exit(-1)

        if not self._args.auto_hostname:
            hostname = self._args.hostname
        else:
            print('Trying to discover your hostname...')
            hostname = discover_hostname()
            if not hostname:
                print('Aborting because we could not discover your hostname.')
                print('Try again or run without --auto-hostname.')
                sys.exit(-1)
            print('Hostname discovered and set to {}'.format(hostname))
        return hostname

    def create_peer_id(self) -> PeerId:
        if not self._args.peer:
            peer_id = PeerId()
        else:
            data = json.load(open(self._args.peer, 'r'))
            peer_id = PeerId.create_from_json(data)
        return peer_id

    def create_wallet(self) -> BaseWallet:
        if self._args.wallet == 'hd':
            kwargs: dict[str, Any] = {
                'words': self._args.words,
            }

            if self._args.passphrase:
                wallet_passphrase = getpass.getpass(prompt='HD Wallet passphrase:')
                kwargs['passphrase'] = wallet_passphrase.encode()

            if self._args.data:
                kwargs['directory'] = self._args.data

            return HDWallet(**kwargs)
        elif self._args.wallet == 'keypair':
            print('Using KeyPairWallet')
            if self._args.data:
                wallet = Wallet(directory=self._args.data)
            else:
                wallet = Wallet()

            wallet.flush_to_disk_interval = 5  # seconds

            if self._args.unlock_wallet:
                wallet_passwd = getpass.getpass(prompt='Wallet password:')
                wallet.unlock(wallet_passwd.encode())

            return wallet
        else:
            raise BuilderError('Invalid type of wallet')
