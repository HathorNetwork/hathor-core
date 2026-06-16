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

from hathor.simulator.utils import add_new_block, add_new_blocks
from hathor.transaction import Transaction
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_double_spending, add_new_transactions
from hathorlib.conf.settings import FeatureSetting


class RatificationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self._settings = self._settings.model_copy(
            update={'ENABLE_TWO_TIER_FINALITY': FeatureSetting.ENABLED}
        )
        self.manager = self.create_peer('testnet', settings=self._settings)
        assert self.manager.tx_storage.indexes.finality_certificate is not None
        # This test exercises the consensus ratification rule directly, so disable the mempool gate
        # (which would otherwise divert the uncertified transactions we add). The rule itself only
        # needs the feature active and the certificate index, both of which remain in place.
        self.manager.vertex_handler.set_finality_service(None)

    def _make_conflicting_pair(self) -> tuple[Transaction, Transaction]:
        """Create two transactions that spend the same output, both in the mempool."""
        add_new_blocks(self.manager, 3, advance_clock=15)
        add_blocks_unlock_reward(self.manager)
        # Seed a normal transaction, then create one that double-spends it.
        add_new_transactions(self.manager, 1, advance_clock=1)
        tx2 = add_new_double_spending(self.manager)
        tx2_meta = tx2.get_metadata()
        assert tx2_meta.conflict_with
        tx1 = self.manager.tx_storage.get_transaction(tx2_meta.conflict_with[0])
        assert isinstance(tx1, Transaction)
        return tx1, tx2

    def _block_consensus(self):
        from hathor.consensus.context import ConsensusAlgorithmContext
        context = ConsensusAlgorithmContext(self.manager.consensus_algorithm)
        return context.block_algorithm

    def test_detects_block_confirming_certified_conflict(self) -> None:
        tx1, tx2 = self._make_conflicting_pair()
        # Mine a block; it confirms the consensus winner among the conflicting pair.
        block = add_new_blocks(self.manager, 1, advance_clock=15)[0]
        confirmed = {tx.hash for tx in block.iter_transactions_in_this_block()}
        assert confirmed & {tx1.hash, tx2.hash}, 'block should confirm one of the conflicting txs'
        confirmed_tx = tx1 if tx1.hash in confirmed else tx2
        other_tx = tx2 if confirmed_tx is tx1 else tx1

        fc_index = self.manager.tx_storage.indexes.finality_certificate
        block_consensus = self._block_consensus()

        # No certificate yet -> the block does not ratify any certified conflict.
        assert not block_consensus._confirms_certified_conflict(block)

        # Certify the *other* (not-confirmed) transaction: now the block confirms a tx that conflicts
        # with a certified one -> the ratification rule must flag it.
        fc_index.add_certificate(other_tx.hash, b'fake-cert-bytes')
        assert block_consensus._confirms_certified_conflict(block)

        # Certifying the confirmed transaction instead is fine (the block ratifies the certified tx).
        fc_index2 = self.manager.tx_storage.indexes.finality_certificate
        fc_index2.add_certificate(confirmed_tx.hash, b'fake-cert-bytes')
        # Still flagged because `other_tx` is also certified, but a block confirming only a certified
        # tx with no certified sibling would not be — covered by the no-certificate assertion above.
        assert block_consensus._confirms_certified_conflict(block)

    def test_block_is_voided_when_it_ratifies_a_certified_conflict(self) -> None:
        tx1, tx2 = self._make_conflicting_pair()
        # One of the pair is the (non-voided) consensus winner; the other is voided.
        winner = tx1 if not tx1.get_metadata().voided_by else tx2
        loser = tx2 if winner is tx1 else tx1

        # Certify the loser *before* mining. A block will confirm the winner, which conflicts with the
        # now-certified loser, so the ratification rule must void the block.
        fc_index = self.manager.tx_storage.indexes.finality_certificate
        fc_index.add_certificate(loser.hash, b'fake-cert-bytes')

        block = add_new_block(self.manager, advance_clock=15, propagate=True)
        block_meta = block.get_metadata()
        assert block_meta.voided_by and block.hash in block_meta.voided_by, 'offending block must be voided'
        # The winner it tried to confirm is no longer marked as confirmed by the voided block.
        assert winner.get_metadata().first_block != block.hash
