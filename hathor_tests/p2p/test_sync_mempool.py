import base64

from hathor.crypto.util import decode_address
from hathor.graphviz import GraphvizVisualizer
from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.simulator import FakeConnection
from hathor.transaction import Block, Transaction
from hathor.util import json_loadb, not_none
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class SyncMempoolTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.network = 'testnet'
        self.manager1 = self.create_peer(self.network, unlock_wallet=True)
        self.manager1.avg_time_between_blocks = 4

        self.genesis = self.manager1.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]

    def _add_new_tx(self, address: str, value: int) -> Transaction:
        from hathor.transaction import Transaction
        from hathor.wallet.base_wallet import WalletOutputInfo

        outputs = []
        outputs.append(
            WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None))

        tx: Transaction = self.manager1.wallet.prepare_transaction_compute_inputs(
            Transaction, outputs, self.manager1.tx_storage
        )
        tx.timestamp = int(self.clock.seconds())
        tx.storage = self.manager1.tx_storage
        tx.weight = 10
        tx.parents = self.manager1.get_new_tx_parents()
        self.manager1.cpu_mining_service.resolve(tx)
        self.manager1.propagate_tx(tx)
        self.clock.advance(10)
        return tx

    def _add_new_transactions(self, num_txs: int) -> list[Transaction]:
        txs = []
        for _ in range(num_txs):
            address = not_none(self.get_address(0))
            value = self.rng.choice([5, 10, 50, 100, 120])
            tx = self._add_new_tx(address, value)
            txs.append(tx)
        return txs

    def _add_new_block(self, propagate: bool = True) -> Block:
        block: Block = self.manager1.generate_mining_block()
        self.assertTrue(self.manager1.cpu_mining_service.resolve(block))
        self.manager1.on_new_tx(block, propagate_to_peers=propagate)
        self.clock.advance(10)
        return block

    def _add_new_blocks(self, num_blocks: int, propagate: bool = True) -> list[Block]:
        blocks = []
        for _ in range(num_blocks):
            blocks.append(self._add_new_block(propagate=propagate))
        return blocks

    def test_mempool_basic(self) -> None:
        # 10 blocks
        self._add_new_blocks(2)
        # N blocks to unlock the reward
        add_blocks_unlock_reward(self.manager1)

        # 5 transactions to be confirmed by the next blocks
        self._add_new_transactions(5)
        # 2 more blocks
        self._add_new_blocks(2)
        # 30 transactions in the mempool
        self._add_new_transactions(30)

        debug_pdf = False
        if debug_pdf:
            dot1 = GraphvizVisualizer(self.manager1.tx_storage, include_verifications=True, include_funds=True).dot()
            dot1.render('mempool-test')

        self.manager2 = self.create_peer(self.network)
        self.assertEqual(self.manager2.state, self.manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, self.manager2)
        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(self.manager2)
        self.assertConsensusEqual(self.manager1, self.manager2)

        # 3 genesis
        # 25 blocks
        # Unlock reward blocks
        # 8 txs
        self.assertEqual(len(self.manager2.tx_storage.indexes.mempool_tips.get()), 1)
        self.assertEqual(len(self.manager1.tx_storage.indexes.mempool_tips.get()), 1)

    def test_mempool_invalid_new_tx(self) -> None:
        # 10 blocks
        self._add_new_blocks(2)
        # N blocks to unlock the reward
        add_blocks_unlock_reward(self.manager1)

        # 5 transactions to be confirmed by the next blocks
        self._add_new_transactions(5)
        # 2 more blocks
        self._add_new_blocks(2)
        # 30 transactions in the mempool
        txs = self._add_new_transactions(30)

        self.manager2 = self.create_peer(self.network)
        self.assertEqual(self.manager2.state, self.manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, self.manager2)

        # inject invalid tx in manager1 to be sent to manager2 through mempool-sync
        invalid_tx = txs[0].clone()
        invalid_tx.parents[1] = invalid_tx.parents[0]  # duplicate parents
        cpu_mining = CpuMiningService()
        cpu_mining.resolve(invalid_tx)
        self.manager1.tx_storage.save_transaction(invalid_tx)
        self.manager1.tx_storage.indexes.mempool_tips.update(invalid_tx)
        self.log.debug('YYY invalid tx injected', tx=invalid_tx.hash_hex)

        # advance until the invalid transaction is requested
        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)
            msg = conn.peek_tr2_value()
            if not msg.startswith(b'GET-DATA'):
                continue
            request = json_loadb(msg.partition(b' ')[2])
            if request.get('origin') == 'mempool' and request['txid'] == invalid_tx.hash_hex:
                break
        else:
            self.fail('took too many iterations')

        request_txid = request['txid']

        # keep going until the response is sent
        for _ in range(10):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)
            msg = conn.peek_tr1_value()
            if not msg.startswith(b'DATA'):
                continue
            _, _, payload = msg.partition(b' ')
            origin, _, tx_encoded = payload.partition(b' ')
            self.assertEqual(origin, b'mempool')
            tx_data = base64.b64decode(tx_encoded)
            tx = self.manager2.vertex_parser.deserialize(tx_data)
            self.assertEqual(tx.hash_hex, request_txid)
            break
        else:
            self.fail('took too many iterations')

        # manager2 will fail to add the transaction and will start to disconnect
        self.assertFalse(conn.tr2.disconnecting)
        conn.run_one_step(debug=True)
        self.assertTrue(conn.tr2.disconnecting)
