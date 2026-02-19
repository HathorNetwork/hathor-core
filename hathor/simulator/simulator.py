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
from typing import TYPE_CHECKING, Any, Generator, Optional

from mnemonic import Mnemonic
from structlog import get_logger

from hathor.builder import BuildArtifacts, Builder
from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.manager import HathorManager
from hathor.p2p.peer import PrivatePeer
from hathor.reactor import ReactorProtocol as Reactor
from hathor.simulator.clock import HeapClock, MemoryReactorHeapClock
from hathor.simulator.miner.geometric_miner import GeometricMiner
from hathor.simulator.patches import SimulatorCpuMiningService, SimulatorVertexVerifier
from hathor.simulator.tx_generator import RandomTransactionGenerator
from hathor.transaction.storage import TransactionStorage
from hathor.util import Random
from hathor.verification.vertex_verifiers import VertexVerifiers
from hathor.wallet import HDWallet

if TYPE_CHECKING:
    from hathor.simulator.fake_connection import FakeConnection
    from hathor.simulator.trigger import Trigger


logger = get_logger()

DEFAULT_STEP_INTERVAL: float = 0.25
DEFAULT_STATUS_INTERVAL: float = 60.0
SIMULATOR_AVG_TIME_BETWEEN_BLOCKS: int = 64


class Simulator:
    def __init__(self, seed: Optional[int] = None):
        self.log = logger.new()
        if seed is None:
            seed = secrets.randbits(64)
        self.seed = seed
        self.rng = Random(self.seed)
        self.settings = get_global_settings().model_copy(
            update={"AVG_TIME_BETWEEN_BLOCKS": SIMULATOR_AVG_TIME_BETWEEN_BLOCKS}
        )
        self._clock = MemoryReactorHeapClock()
        self._peers: OrderedDict[str, HathorManager] = OrderedDict()
        self._connections: list['FakeConnection'] = []
        self._started = False

    def start(self) -> None:
        """Has to be called before any other method can be called."""
        assert not self._started
        self._started = True
        first_timestamp = self.settings.GENESIS_BLOCK_TIMESTAMP
        dt = self.rng.randint(3600, 120 * 24 * 3600)
        self._clock.advance(first_timestamp + dt)
        self.log.debug('randomized step: clock advance start', dt=dt)

    def stop(self) -> None:
        """Can only stop after calling start, but it doesn't matter if it's paused or not"""
        assert self._started
        self._started = False

    def get_default_builder(self) -> Builder:
        """
        Returns a builder with default configuration, for convenience when using create_peer() or create_artifacts()
        """
        return Builder() \
            .set_peer(PrivatePeer.auto_generated()) \
            .set_soft_voided_tx_ids(set()) \
            .enable_sync_v2() \
            .set_settings(self.settings)

    def create_peer(self, builder: Optional[Builder] = None) -> HathorManager:
        """
        Returns a manager from a builder, after configuring it for simulator use.
        You may get a builder from get_default_builder() for convenience.
        """
        artifacts = self.create_artifacts(builder)
        return artifacts.manager

    def create_artifacts(self, builder: Optional[Builder] = None) -> BuildArtifacts:
        """
        Returns build artifacts from a builder, after configuring it for simulator use.
        You may get a builder from get_default_builder() for convenience.
        """
        assert self._started, 'Simulator is not started.'
        builder = builder or self.get_default_builder()

        wallet = HDWallet(gap_limit=2, settings=self.settings)
        wallet._manually_initialize()

        cpu_mining_service = SimulatorCpuMiningService()
        daa = DifficultyAdjustmentAlgorithm(settings=self.settings)

        artifacts = builder \
            .set_reactor(self._clock) \
            .set_rng(Random(self.rng.getrandbits(64))) \
            .set_wallet(wallet) \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_daa(daa) \
            .set_cpu_mining_service(cpu_mining_service) \
            .build()

        artifacts.manager.start()
        self._clock.run()
        self.run_to_completion()

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(self.rng.randbytes(32))
        self.log.debug('randomized step: generate wallet', words=words)
        wallet.unlock(words=words, tx_storage=artifacts.tx_storage)

        return artifacts

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

    def remove_connection(self, conn: 'FakeConnection') -> None:
        self._connections.remove(conn)

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
                           min_interval: float = 0.0,
                           step: float = DEFAULT_STEP_INTERVAL,
                           status_interval: float = DEFAULT_STATUS_INTERVAL) -> bool:
        """ Will stop when all peers have synced/errored (-> True), or when max_interval is elapsed (-> False).

        Optionally keep running for at least `min_interval` ignoring the stop condition.

        Make sure miners/tx_generators are stopped or this will almost certainly run until max_interval.
        """
        assert self._started
        steps = 0
        interval = 0.0
        initial = self._clock.seconds()
        for _ in self._run(max_interval, step, status_interval):
            steps += 1
            latest_time = self._clock.seconds()
            interval = latest_time - initial
            if interval > min_interval and all(not conn.can_step() for conn in self._connections):
                self.log.debug('run_until_complete: all done', steps=steps, dt=interval)
                return True
        self.log.debug('run_until_complete: max steps exceeded', steps=steps, dt=interval)
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


def _build_vertex_verifiers(
    reactor: Reactor,
    settings: HathorSettings,
    daa: DifficultyAdjustmentAlgorithm,
    feature_service: FeatureService,
    tx_storage: TransactionStorage,
) -> VertexVerifiers:
    """
    A custom VertexVerifiers builder to be used by the simulator.
    """
    return VertexVerifiers.create(
        reactor=reactor,
        settings=settings,
        vertex_verifier=SimulatorVertexVerifier(reactor=reactor, settings=settings, feature_service=feature_service),
        daa=daa,
        feature_service=feature_service,
        tx_storage=tx_storage,
    )
