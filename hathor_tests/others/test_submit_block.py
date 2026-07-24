#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from twisted.internet.defer import ensureDeferred

from hathor.manager import HathorManager
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Block
from hathor_tests.simulation.base import SimulatorTestCase


class SubmitBlockTestCase(SimulatorTestCase):
    __test__ = True

    def _make_candidate(self, manager: HathorManager, data: bytes) -> Block:
        """Create and resolve (but do not propagate) a block on the current tip."""
        block = manager.generate_mining_block(data=data)
        manager.cpu_mining_service.resolve(block)
        return block

    def test_no_delay_accepts(self) -> None:
        manager = self.create_peer()
        add_new_blocks(manager, 5, advance_clock=15)
        candidate = self._make_candidate(manager, b'candidate')

        results: list[bool] = []
        ensureDeferred(manager.asubmit_block(candidate)).addCallback(results.append)

        # with no delay the coroutine completes synchronously
        self.assertEqual(results, [True])
        self.assertTrue(manager.tx_storage.transaction_exists(candidate.hash))

    def test_ignore_rejects_without_processing(self) -> None:
        manager = self.create_peer()
        add_new_blocks(manager, 5, advance_clock=15)
        candidate = self._make_candidate(manager, b'candidate')

        manager.ignore_mining_submissions = True
        results: list[bool] = []
        ensureDeferred(manager.asubmit_block(candidate)).addCallback(results.append)

        self.assertEqual(results, [False])
        self.assertFalse(manager.tx_storage.transaction_exists(candidate.hash))

    def test_delay_accepts_when_tip_unchanged(self) -> None:
        manager = self.create_peer()
        add_new_blocks(manager, 5, advance_clock=15)
        candidate = self._make_candidate(manager, b'candidate')

        manager.mining_submission_delay = 2
        results: list[bool] = []
        ensureDeferred(manager.asubmit_block(candidate)).addCallback(results.append)

        # processing is deferred: nothing happened yet
        self.assertEqual(results, [])
        self.assertFalse(manager.tx_storage.transaction_exists(candidate.hash))

        assert hasattr(manager.reactor, 'advance')
        manager.reactor.advance(2)

        # the tip never moved, so the block is accepted
        self.assertEqual(results, [True])
        self.assertTrue(manager.tx_storage.transaction_exists(candidate.hash))

    def test_delay_rejects_when_tip_advances(self) -> None:
        manager = self.create_peer()
        add_new_blocks(manager, 5, advance_clock=15)
        candidate = self._make_candidate(manager, b'candidate')

        manager.mining_submission_delay = 2
        results: list[bool] = []
        ensureDeferred(manager.asubmit_block(candidate)).addCallback(results.append)
        self.assertEqual(results, [])

        # a competing block found elsewhere arrives and advances the local tip
        competing = self._make_candidate(manager, b'competing')
        self.assertTrue(manager.propagate_tx(competing))
        self.assertEqual(manager.tx_storage.get_best_block_hash(), competing.hash)

        assert hasattr(manager.reactor, 'advance')
        manager.reactor.advance(2)

        # the parent-tip guard now rejects the would-be sibling, nothing was stored
        self.assertEqual(results, [False])
        self.assertFalse(manager.tx_storage.transaction_exists(candidate.hash))
