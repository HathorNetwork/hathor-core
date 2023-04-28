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

import secrets
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Generator, List, Optional, Set

from mnemonic import Mnemonic
from structlog import get_logger

from hathor.builder import Builder
from hathor.conf import HathorSettings
from hathor.daa import TestMode, _set_test_mode
from hathor.event.websocket import EventWebsocketFactory
from hathor.manager import HathorManager
from hathor.p2p.peer_id import PeerId
from hathor.simulator.clock import HeapClock
from hathor.simulator.miner.geometric_miner import GeometricMiner
from hathor.simulator.tx_generator import RandomTransactionGenerator
from hathor.transaction.genesis import _get_genesis_transactions_unsafe
from hathor.util import Random
from hathor.wallet import HDWallet

if TYPE_CHECKING:
    from hathor.simulator.fake_connection import FakeConnection
    from hathor.simulator.trigger import Trigger


logger = get_logger()

DEFAULT_STEP_INTERVAL: float = 0.25
DEFAULT_STATUS_INTERVAL: float = 60.0


class Simulator:
    # used to concilite monkeypatching and multiple instances
    _patches_rc: int = 0

    @classmethod
    def _apply_patches(cls):
        """ Applies global patches on modules that aren't easy/possible to configure otherwise.

        Patches:

        - disable pow verification
        - set DAA test-mode to DISABLED (will actually run the pow function, that won't actually verify the pow)
        - override AVG_TIME_BETWEEN_BLOCKS to 64
        """
        from hathor.transaction import BaseTransaction

        def verify_pow(self: BaseTransaction, *args: Any, **kwargs: Any) -> None:
            assert self.hash is not None
            logger.new().debug('Skipping BaseTransaction.verify_pow() for simulator')

        cls._original_verify_pow = BaseTransaction.verify_pow
        BaseTransaction.verify_pow = verify_pow

        _set_test_mode(TestMode.DISABLED)

        from hathor import daa
        cls._original_avg_time_between_blocks = daa.AVG_TIME_BETWEEN_BLOCKS
        daa.AVG_TIME_BETWEEN_BLOCKS = 64

    @classmethod
    def _remove_patches(cls):
        """ Remove the patches previously applied.
        """
        from hathor.transaction import BaseTransaction
        BaseTransaction.verify_pow = cls._original_verify_pow

        from hathor import daa
        daa.AVG_TIME_BETWEEN_BLOCKS = cls._original_avg_time_between_blocks

    @classmethod
    def _patches_rc_increment(cls):
        """ This is used by when starting instances of Simulator to determine when to run _apply_patches"""
        assert cls._patches_rc >= 0
        cls._patches_rc += 1
        if cls._patches_rc == 1:
            # patches not yet applied
            cls._apply_patches()

    @classmethod
    def _patches_rc_decrement(cls):
        """ This is used by when stopping instances of Simulator to determine when to run _remove_patches"""
        assert cls._patches_rc > 0
        cls._patches_rc -= 1
        if cls._patches_rc == 0:
            # patches not needed anymore
            cls._remove_patches()

    def __init__(self, seed: Optional[int] = None):
        self.log = logger.new()
        if seed is None:
            seed = secrets.randbits(64)
        self.seed = seed
        self.rng = Random(self.seed)
        self.settings = HathorSettings()
        self._network = 'testnet'
        self._clock = HeapClock()
        self._peers: OrderedDict[str, HathorManager] = OrderedDict()
        self._connections: List['FakeConnection'] = []
        self._started = False

    def start(self) -> None:
        """Has to be called before any other method can be called."""
        assert not self._started
        self._started = True
        self._patches_rc_increment()
        first_timestamp = min(tx.timestamp for tx in _get_genesis_transactions_unsafe(None))
        dt = self.rng.randint(3600, 120 * 24 * 3600)
        self._clock.advance(first_timestamp + dt)
        self.log.debug('randomized step: clock advance start', dt=dt)

    def stop(self) -> None:
        """Can only stop after calling start, but it doesn't matter if it's paused or not"""
        assert self._started
        self._started = False
        self._patches_rc_decrement()

    def create_peer(
        self,
        network: Optional[str] = None,
        peer_id: Optional[PeerId] = None,
        enable_sync_v1: bool = True,
        enable_sync_v2: bool = True,
        soft_voided_tx_ids: Optional[Set[bytes]] = None,
        full_verification: bool = True,
        event_ws_factory: Optional[EventWebsocketFactory] = None
    ) -> HathorManager:
        assert self._started, 'Simulator is not started.'
        assert peer_id is not None  # XXX: temporary, for checking that tests are using the peer_id

        wallet = HDWallet(gap_limit=2)
        wallet._manually_initialize()

        builder = Builder() \
            .set_reactor(self._clock) \
            .set_peer_id(peer_id or PeerId()) \
            .set_network(network or self._network) \
            .set_wallet(wallet) \
            .set_rng(Random(self.rng.getrandbits(64))) \
            .set_enable_sync_v1(enable_sync_v1) \
            .set_enable_sync_v2(enable_sync_v2) \
            .set_full_verification(full_verification) \
            .set_soft_voided_tx_ids(soft_voided_tx_ids or set()) \
            .use_memory()

        if event_ws_factory:
            builder.enable_event_manager(event_ws_factory=event_ws_factory)

        artifacts = builder.build()

        artifacts.manager.start()
        self.run_to_completion()

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(self.rng.randbytes(32))
        self.log.debug('randomized step: generate wallet', words=words)
        wallet.unlock(words=words, tx_storage=artifacts.tx_storage)

        return artifacts.manager

    def create_tx_generator(self, peer: HathorManager, *args: Any, **kwargs: Any) -> RandomTransactionGenerator:
        return RandomTransactionGenerator(peer, self.rng, *args, **kwargs)

    def create_miner(self, peer: HathorManager, *args: Any, **kwargs: Any) -> GeometricMiner:
        return GeometricMiner(peer, self.rng, *args, **kwargs)

    def run_to_completion(self):
        """ This will advance the test's clock until all calls scheduled are done.
        """
        assert self._started
        for call in self._clock.getDelayedCalls():
            amount = max(0, call.getTime() - self._clock.seconds())
            self._clock.advance(amount)

    def add_peer(self, name: str, peer: HathorManager) -> None:
        assert self._started
        if name in self._peers:
            raise ValueError('Duplicate peer name')
        self._peers[name] = peer

    def get_reactor(self) -> HeapClock:
        return self._clock

    def get_peer(self, name: str) -> HathorManager:
        return self._peers[name]

    def add_connection(self, conn: 'FakeConnection') -> None:
        self._connections.append(conn)

    def _run(self, interval: float, step: float, status_interval: float) -> Generator[None, None, None]:
        """ Implementation of run, yields at every step to allow verifications like in run_until_complete
        """
        assert self._started
        initial = self._clock.seconds()
        latest_time = self._clock.seconds()
        t0 = time.time()
        while self._clock.seconds() <= initial + interval:
            for conn in self._connections:
                conn.run_one_step()
            yield
            if self._clock.seconds() - latest_time >= status_interval:
                t1 = time.time()
                # Real elapsed time.
                real_elapsed_time = t1 - t0
                # Rate is the number of simulated seconds per real second.
                # For example, a rate of 60 means that we can simulate 1 minute per second.
                rate: Optional[float] = None
                if real_elapsed_time != 0:
                    rate = (self._clock.seconds() - initial) / real_elapsed_time
                # Simulation now.
                sim_now = self._clock.seconds()
                # Simulation dt.
                sim_dt = self._clock.seconds() - initial
                # Number of simulated seconds to end this run.
                sim_remaining = interval - self._clock.seconds() + initial
                # Number of call pending to be executed.
                delayed_calls = len(self._clock.getDelayedCalls())
                self.log.info('simulator: time step', real_elapsed_time=real_elapsed_time, rate=rate, sim_now=sim_now,
                              dt_step=sim_dt, dt_remaining=sim_remaining, delayed_calls=delayed_calls)
                latest_time = self._clock.seconds()
            self._clock.advance(step)

    def run_until_complete(self,
                           max_interval: float,
                           step: float = DEFAULT_STEP_INTERVAL,
                           status_interval: float = DEFAULT_STATUS_INTERVAL) -> bool:
        """ Will stop when all peers have synced/errored (-> True), or when max_interval is elapsed (-> False).

        Make sure miners/tx_generators are stopped or this will almost certainly run until max_interval.
        """
        assert self._started
        for _ in self._run(max_interval, step, status_interval):
            if all(not conn.can_step() for conn in self._connections):
                return True
        return False

    def run(self,
            interval: float,
            step: float = DEFAULT_STEP_INTERVAL,
            status_interval: float = DEFAULT_STATUS_INTERVAL,
            *,
            trigger: Optional['Trigger'] = None) -> bool:
        """Return True if it successfully ends the execution.

        If no trigger is provided, it always returns True.
        If a trigger is provided, it returns True if the trigger stops the execution. Otherwise, it returns False.
        """
        assert self._started
        for _ in self._run(interval, step, status_interval):
            if trigger is not None and trigger.should_stop():
                return True
        if trigger is not None:
            return False
        return True
