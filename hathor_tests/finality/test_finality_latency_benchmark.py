# Copyright 2026 Hathor Labs
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

"""
End-to-end finality latency benchmark.

Measures how long a finality-eligible transaction takes to collect a quorum (weight ``>= 2f+1``) of
validator votes and be **admitted to the mempool** as certified, as a function of two parameters:

* the **number of validators** in the committee (``N``), and
* the one-way **network latency between validators** (``L``).

It complements ``plans/bls-benchmark.md`` (which times the raw BLS primitives in isolation). Here we
drive the *whole* validator fast path — pin, sign, flood, accumulate votes, assemble the certificate,
verify it, and admit the transaction — through the real `FinalityService`, but over a **discrete-event
simulated network** with a virtual clock:

* every message hop between two validators costs ``L`` of virtual time;
* the real (wall-clock) CPU cost of each handler — dominated by the ``blst`` BLS sign/verify, reached
  through the ``htr_lib`` extension — is measured with ``perf_counter`` and advances the virtual clock
  of the node processing it.

So the reported soft-finality time is ``crypto/CPU work on the critical path`` + ``the network hops to
collect a quorum``. With ``L = 0`` it is the pure node-local certification cost (~a few ms with
``blst``); raising ``L`` adds the flood round-trips (a quorum is collected in ~2 hops thanks to
all-to-all flooding, so the network term is ~``2L`` and roughly independent of ``N``).

This is **not** part of the normal test run (it spins up a manager and, for large committees, does
``O(N^2)`` vote verifications). Enable it:

    HATHOR_FINALITY_BENCH=1 uv run pytest -p no:warnings -s \
        hathor_tests/finality/test_finality_latency_benchmark.py

Parameters (all optional, comma-separated to sweep):

    HATHOR_FINALITY_BENCH_SIZES=4,7,10,13        # number of validators N
    HATHOR_FINALITY_BENCH_LATENCY_MS=0,25,100    # one-way inter-validator latency L (ms)
    HATHOR_FINALITY_BENCH_ITERS=3                # timed iterations per (N, L) cell
"""

import heapq
import os
import sys
import time
import unittest as stdlib_unittest
from collections.abc import Callable, Iterator

from hathor.finality.crypto import FinalityValidatorSigner
from hathor.finality.fc import FinalityCertificate, Vote, indices_from_bitmap
from hathor.finality.finality_settings import FinalitySettings
from hathor.finality.pending_pool import PendingFinalityPool
from hathor.finality.service import FinalityService
from hathor.finality.stores import MemoryFinalityCertificateStore, MemoryFinalityPinStore
from hathor.simulator.utils import add_new_blocks, gen_new_tx
from hathor.transaction import Transaction
from hathor.transaction.storage import TransactionStorage
from hathor_tests import unittest
from hathor_tests.finality.test_service import _committee
from hathor_tests.utils import add_blocks_unlock_reward

_BENCH_ENABLED = bool(os.environ.get('HATHOR_FINALITY_BENCH'))


def _sizes() -> tuple[int, ...]:
    raw = os.environ.get('HATHOR_FINALITY_BENCH_SIZES')
    if raw:
        return tuple(int(part) for part in raw.split(',') if part.strip())
    return (4, 7, 10, 13)


def _latencies_ms() -> tuple[float, ...]:
    raw = os.environ.get('HATHOR_FINALITY_BENCH_LATENCY_MS')
    if raw:
        return tuple(float(part) for part in raw.split(',') if part.strip())
    return (0.0, 25.0, 100.0)


def _iters() -> int:
    return int(os.environ.get('HATHOR_FINALITY_BENCH_ITERS', '3'))


class _SimNetwork:
    """In-process committee over a discrete-event simulated network with a virtual clock.

    Wraps the real `FinalityService` for every validator. Transport sends made by a handler are
    buffered and, once the handler returns, scheduled for delivery at ``virtual_now + handler_cpu +
    latency`` — modelling "process the message, then it takes one network hop to reach the peer". The
    handler CPU is the real `perf_counter` time of the py_ecc work, so the simulation combines measured
    crypto cost with the configured per-hop latency.
    """

    def __init__(
        self,
        settings: FinalitySettings,
        signers: list[FinalityValidatorSigner],
        tx_storage: TransactionStorage,
        latency: float,
    ) -> None:
        self.settings = settings
        self.tx_storage = tx_storage
        self.latency = latency
        self.now = 0.0
        self.first_admit_time: float | None = None
        self._heap: list = []
        self._seq = 0
        self._outbox: list[tuple[int, object]] = []  # (recipient_index, thunk) emitted by current handler
        self._handler_started_at = 0.0
        self.services: dict[int, FinalityService] = {}
        for i, signer in enumerate(signers):
            self.services[i] = FinalityService(
                finality_settings=settings,
                pending_pool=PendingFinalityPool(),
                certificate_store=MemoryFinalityCertificateStore(),
                transport=_SimTransport(self, i),
                admit_certified_tx=self._make_admit(i),
                is_feature_active=lambda: True,
                signer=signer,
                pin_store=MemoryFinalityPinStore(),
            )

    def _make_admit(self, owner: int) -> Callable[[Transaction], bool]:
        def admit(tx: Transaction) -> bool:
            if self.first_admit_time is None:
                # Soft finality fires partway through this handler: virtual arrival of the quorum-
                # completing message plus the CPU spent in this handler up to the admission.
                self.first_admit_time = self.now + (time.perf_counter() - self._handler_started_at)
            return True
        return admit

    def deserialize(self, tx_bytes: bytes) -> Transaction:
        tx = Transaction.create_from_struct(tx_bytes, storage=self.tx_storage)
        tx.storage = self.tx_storage
        return tx

    def emit(self, recipient_index: int, thunk: object) -> None:
        self._outbox.append((recipient_index, thunk))

    def _schedule(self, deliver_at: float, recipient_index: int, thunk: object) -> None:
        heapq.heappush(self._heap, (deliver_at, self._seq, recipient_index, thunk))
        self._seq += 1

    def run(self, initial_thunk: object) -> None:
        self._schedule(0.0, 0, initial_thunk)
        while self._heap:
            deliver_at, _seq, _recipient, thunk = heapq.heappop(self._heap)
            self.now = deliver_at
            self._outbox = []
            self._handler_started_at = time.perf_counter()
            thunk()
            cpu = time.perf_counter() - self._handler_started_at
            send_at = self.now + cpu + self.latency
            for recipient_index, out_thunk in self._outbox:
                self._schedule(send_at, recipient_index, out_thunk)


class _SimTransport:
    """`FinalityTransport` that buffers sends into the simulator instead of delivering synchronously."""

    def __init__(self, network: _SimNetwork, owner: int) -> None:
        self._net = network
        self._owner = owner

    def _others(self, exclude: object | None) -> Iterator[int]:
        for j in self._net.services:
            if j != self._owner and j != exclude:
                yield j

    def submit_to_validator(self, tx_bytes: bytes) -> None:
        target = 0 if self._owner != 0 else 1
        self._net.emit(target, lambda: self._net.services[target].on_submit_finality_tx(
            self._net.deserialize(tx_bytes), source=self._owner))

    def flood_to_validators(self, tx_bytes: bytes, *, exclude: object | None = None) -> None:
        for j in self._others(exclude):
            self._net.emit(j, lambda j=j: self._net.services[j].on_submit_finality_tx(
                self._net.deserialize(tx_bytes), source=self._owner))

    def flood_vote(self, vote_bytes: bytes, *, exclude: object | None = None) -> None:
        for j in self._others(exclude):
            self._net.emit(j, lambda j=j: self._net.services[j].on_vote(
                Vote.from_bytes(vote_bytes), source=self._owner))

    def broadcast_certificate(self, tx_bytes: bytes, fc_bytes: bytes, *, exclude: object | None = None) -> None:
        for j in self._others(exclude):
            self._net.emit(j, lambda j=j: self._net.services[j].on_certificate(
                self._net.deserialize(tx_bytes), FinalityCertificate.from_bytes(fc_bytes), source=self._owner))


@stdlib_unittest.skipUnless(_BENCH_ENABLED, 'set HATHOR_FINALITY_BENCH=1 to run the finality latency benchmark')
class FinalityLatencyBenchmark(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('testnet')
        # Enough block rewards (one per committee size benchmarked) to fund a distinct transaction each.
        add_new_blocks(self.manager, len(_sizes()) + 2, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

    def _new_tx(self) -> Transaction:
        address = self.manager.wallet.get_unused_address(mark_as_used=True)
        return gen_new_tx(self.manager, address, 100)

    def _bench_one(
        self,
        settings: FinalitySettings,
        signers: list[FinalityValidatorSigner],
        tx: Transaction,
        latency: float,
    ) -> tuple[float, int]:
        """Run one full certify round on a fresh simulated network.

        Returns ``(seconds_to_soft_finality, quorum_signers)`` where *seconds_to_soft_finality* is the
        virtual time from submission until the transaction first collects ``>= 2f+1`` votes and is
        admitted to the mempool.
        """
        network = _SimNetwork(settings, signers, self.manager.tx_storage, latency)
        network.run(lambda: network.services[0].on_submit_finality_tx(tx, source=None))
        assert network.first_admit_time is not None, 'transaction was never certified'
        cert_bytes = network.services[0]._certificates.get_certificate(tx.hash)
        assert cert_bytes is not None
        fc = FinalityCertificate.from_bytes(cert_bytes)
        return network.first_admit_time, len(indices_from_bitmap(fc.bitmap))

    def test_benchmark(self) -> None:
        iters = _iters()
        latencies = _latencies_ms()
        rows = []
        for n in _sizes():
            settings, signers = _committee(n)  # committee + PoP verification done once, outside timing
            tx = self._new_tx()
            for latency_ms in latencies:
                latency = latency_ms / 1e3
                samples, quorum = [], 0
                for _ in range(iters):
                    finality_time, quorum = self._bench_one(settings, signers, tx, latency)
                    samples.append(finality_time)
                rows.append((n, settings.f, quorum, latency_ms, min(samples), _median(samples)))

        header = f"{'N':>4} {'f':>3} {'quorum':>7} {'latency':>9} {'finality(best)':>16} {'finality(med)':>15}"
        lines = [header, '-' * len(header)]
        for n, f, quorum, latency_ms, best, med in rows:
            lines.append(f'{n:>4} {f:>3} {quorum:>7} {latency_ms:>6.0f} ms '
                         f'{best * 1e3:>13.1f} ms {med * 1e3:>12.1f} ms')
        report = '\n'.join(lines)
        out_path = os.environ.get('HATHOR_FINALITY_BENCH_OUT')
        if out_path:
            with open(out_path, 'w') as fh:
                fh.write(report + '\n')
        print('\n' + report + '\n', file=sys.stderr)

        for n, f, quorum, *_ in rows:
            assert quorum >= 2 * f + 1


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2
