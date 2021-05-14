import random
import time
from typing import TYPE_CHECKING, Dict, List, Optional

import numpy.random
from mnemonic import Mnemonic

from hathor.manager import HathorManager, TestMode
from hathor.p2p.peer_id import PeerId
from hathor.simulator.clock import HeapClock
from hathor.transaction.genesis import _get_genesis_transactions_unsafe
from hathor.wallet import HDWallet

if TYPE_CHECKING:
    from hathor.simulator.fake_connection import FakeConnection


class Simulator:
    def __init__(self):
        self.set_seed(numpy.random.randint(2**32))
        self.network = 'testnet'
        self.clock = HeapClock()
        self.peers: Dict[str, 'HathorManager'] = {}
        self.connections: List['FakeConnection'] = []

    def start(self):
        self.apply_patches()
        first_timestamp = min(tx.timestamp for tx in _get_genesis_transactions_unsafe(None))
        self.clock.advance(first_timestamp + random.randint(3600, 120*24*3600))

    def stop(self):
        self.remove_patches()

    def create_peer(self, network: Optional[str] = None) -> HathorManager:
        if network is None:
            network = self.network

        wallet = HDWallet(gap_limit=2)
        wallet._manually_initialize()

        # TODO FIXME Peer-id changes even when using the same seed.
        peer_id = PeerId()
        manager = HathorManager(
            self.clock,
            peer_id=peer_id,
            network=network,
            wallet=wallet,
        )

        manager.reactor = self.clock
        manager.test_mode = TestMode.DISABLED
        manager.avg_time_between_blocks = 64
        manager._full_verification = True
        manager.start()
        self.run_to_completion()

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(bytes(random.randint(0, 255) for _ in range(32)))
        wallet.unlock(words=words, tx_storage=manager.tx_storage)
        return manager

    def run_to_completion(self):
        """ This will advance the test's clock until all calls scheduled are done.
        """
        for call in self.clock.getDelayedCalls():
            amount = max(0, call.getTime() - self.clock.seconds())
            self.clock.advance(amount)

    def apply_patches(self):
        from hathor.transaction import BaseTransaction

        def verify_pow(self: BaseTransaction) -> None:
            assert self.hash is not None

        self._original_verify_pow = BaseTransaction.verify_pow
        BaseTransaction.verify_pow = verify_pow

    def remove_patches(self):
        from hathor.transaction import BaseTransaction
        BaseTransaction.verify_pow = self._original_verify_pow

    def add_peer(self, name: str, peer: 'HathorManager') -> None:
        if name in self.peers:
            raise ValueError('Duplicate peer name')
        self.peers[name] = peer

    def get_peer(self, name: str) -> 'HathorManager':
        return self.peers[name]

    def add_connection(self, conn: 'FakeConnection') -> None:
        self.connections.append(conn)

    def set_seed(self, seed: int) -> None:
        self.seed = seed
        random.seed(self.seed)
        numpy.random.seed(self.seed)

    def run(self, interval: float, step: float = 0.25, status_interval: float = 60.0) -> None:
        initial = self.clock.seconds()
        latest_time = self.clock.seconds()
        t0 = time.time()
        while self.clock.seconds() <= initial + interval:
            for conn in self.connections:
                conn.run_one_step()
            if self.clock.seconds() - latest_time >= status_interval:
                t1 = time.time()
                # Real elapsed time.
                real_elapsed_time = t1 - t0
                # Rate is the number of simulated seconds per real second.
                # For example, a rate of 60 means that we can simulate 1 minute per second.
                rate = (self.clock.seconds() - initial) / (t1 - t0)
                # Simulation now.
                sim_now = self.clock.seconds()
                # Simulation dt.
                sim_dt = self.clock.seconds() - initial
                # Number of simulated seconds to end this run.
                sim_remaining = interval - self.clock.seconds() + initial
                # Number of call pending to be executed.
                delayed_calls = len(self.clock.getDelayedCalls())
                print(f'[{real_elapsed_time:8.2f}][rate={rate:8.2f}] '
                      f't={sim_now:15.2f}    dt={sim_dt:8.2f}    toBeRun={sim_remaining:8.2f}    '
                      f'delayedCalls={delayed_calls}')
                latest_time = self.clock.seconds()
            self.clock.advance(step)
