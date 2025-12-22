# Copyright 2025 Hathor Labs
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

from unittest.mock import patch

from hathor.simulator.utils import add_new_blocks, gen_new_tx
from hathor_tests import unittest


class MempoolIterAllTraversalTestCase(unittest.TestCase):
    """Regression helpers for ByteCollectionMempoolTipsIndex.iter_all."""

    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('testnet', unlock_wallet=True)

    def test_iter_mempool_walks_block_chain_via_inputs(self) -> None:
        # Mine enough blocks so at least one reward is spendable by the wallet.
        num_blocks = self._settings.REWARD_SPEND_MIN_BLOCKS + 2
        add_new_blocks(self.manager, num_blocks, advance_clock=1)
        self.run_to_completion()

        address = self.get_address(0)
        assert address is not None
        tx = gen_new_tx(self.manager, address, value=10)
        self.manager.propagate_tx(tx)
        self.run_to_completion()

        # Capture which vertices iter_mempool touches while walking dependencies.
        with patch.object(self.manager.tx_storage, 'get_vertex',
                          wraps=self.manager.tx_storage.get_vertex) as get_vertex:
            mempool = list(self.manager.tx_storage.iter_mempool())

        self.assertEqual({tx.hash}, {t.hash for t in mempool})

        tx_storage = self.manager.tx_storage
        expected_blocks = {
            txin.tx_id
            for txin in tx.inputs
            if tx_storage.get_transaction(txin.tx_id).is_block
        }
        visited_blocks = {
            call.args[0]
            for call in get_vertex.call_args_list
            if tx_storage.get_transaction(call.args[0]).is_block
        }

        # iter_mempool should only touch the blocks whose outputs are being spent in the mempool.
        self.assertTrue(expected_blocks, 'at least one block reward should be spent')
        self.assertEqual(expected_blocks, visited_blocks)
