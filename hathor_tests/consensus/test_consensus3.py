import pytest

from hathor.simulator.utils import add_new_block, add_new_blocks
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class DoubleSpendingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.network = 'testnet'
        self.manager1 = self.create_peer(self.network, unlock_wallet=True)

    @pytest.mark.xfail(strict=True)
    def test_double_spending_attempt_1(self) -> None:
        manager = self.manager1

        add_new_blocks(manager, 5, advance_clock=15)
        add_blocks_unlock_reward(manager)

        from hathor.crypto.util import decode_address
        from hathor.graphviz import GraphvizVisualizer
        from hathor.transaction import Transaction
        from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo

        graphviz = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True)

        addr = manager.wallet.get_unused_address()
        outputs = []
        outputs.append(WalletOutputInfo(decode_address(addr), 1, None))
        outputs.append(WalletOutputInfo(decode_address(addr), 1000, None))
        outputs.append(WalletOutputInfo(decode_address(addr), 6400 - 1001, None))
        tx_fund0 = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, manager.tx_storage)
        tx_fund0.weight = 1
        tx_fund0.parents = manager.get_new_tx_parents()
        tx_fund0.timestamp = int(self.clock.seconds())
        manager.cpu_mining_service.resolve(tx_fund0)
        self.assertTrue(manager.propagate_tx(tx_fund0))

        def do_step(tx_fund: Transaction) -> Transaction:
            inputs = [WalletInputInfo(tx_fund.hash, 0, manager.wallet.get_private_key(addr))]
            outputs = [WalletOutputInfo(decode_address(addr), 1, None)]
            tx1 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx_fund.timestamp+1)
            tx1.weight = 1
            tx1.parents = manager.get_new_tx_parents(tx1.timestamp)
            manager.cpu_mining_service.resolve(tx1)
            self.assertTrue(manager.propagate_tx(tx1))

            inputs = []
            inputs.append(WalletInputInfo(tx1.hash, 0, manager.wallet.get_private_key(addr)))
            inputs.append(WalletInputInfo(tx_fund.hash, 1, manager.wallet.get_private_key(addr)))
            outputs = [WalletOutputInfo(decode_address(addr), tx_fund.outputs[1].value+1, None)]
            tx2 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx1.timestamp+1)
            tx2.weight = 1
            tx2.parents = manager.get_new_tx_parents(tx2.timestamp)
            manager.cpu_mining_service.resolve(tx2)
            self.assertTrue(manager.propagate_tx(tx2))

            inputs = [WalletInputInfo(tx_fund.hash, 0, manager.wallet.get_private_key(addr))]
            outputs = [WalletOutputInfo(decode_address(addr), 1, None)]
            tx3 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx_fund.timestamp+1)
            tx3.weight = tx1.weight + tx2.weight + 0.1
            tx3.parents = manager.get_new_tx_parents(tx3.timestamp)
            manager.cpu_mining_service.resolve(tx3)
            self.assertTrue(manager.propagate_tx(tx3))

            inputs = [WalletInputInfo(tx_fund.hash, 1, manager.wallet.get_private_key(addr))]
            outputs = [WalletOutputInfo(decode_address(addr), tx_fund.outputs[1].value, None)]
            tx4 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx_fund.timestamp+1)
            tx4.weight = 1
            tx4.parents = manager.get_new_tx_parents(tx4.timestamp)
            manager.cpu_mining_service.resolve(tx4)
            self.assertTrue(manager.propagate_tx(tx4))

            inputs = []
            inputs.append(WalletInputInfo(tx2.hash, 0, manager.wallet.get_private_key(addr)))
            inputs.append(WalletInputInfo(tx4.hash, 0, manager.wallet.get_private_key(addr)))
            outputs = []
            outputs.append(WalletOutputInfo(decode_address(addr), 1, None))
            outputs.append(WalletOutputInfo(decode_address(addr), 2*tx_fund.outputs[1].value, None))
            tx5: Transaction = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx2.timestamp+1)
            tx5.weight = tx3.weight - tx1.weight + 0.1
            tx5.parents = [tx2.hash, tx4.hash]
            manager.cpu_mining_service.resolve(tx5)
            self.assertTrue(manager.propagate_tx(tx5))
            return tx5

        tx = tx_fund0
        N = 10
        for _ in range(N):
            tx = do_step(tx)

        block = add_new_block(manager)
        self.assertIn(tx.hash, block.parents)

        dot = graphviz.dot()
        dot.render('dot0')

        meta = tx.get_metadata()
        self.assertIsNone(meta.conflict_with)
        self.assertIsNone(meta.voided_by)
        self.assertEqual(tx.outputs[1].value, 1000 * 2**N)

        self.assertConsensusValid(manager)

    @pytest.mark.xfail(strict=True)
    def test_double_spending_attempt_2(self) -> None:
        manager = self.manager1

        add_new_blocks(manager, 5, advance_clock=15)
        add_blocks_unlock_reward(manager)

        from hathor.crypto.util import decode_address
        from hathor.transaction import Transaction
        from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo

        addr = manager.wallet.get_unused_address()
        outputs = []
        outputs.append(WalletOutputInfo(decode_address(addr), 1, None))
        outputs.append(WalletOutputInfo(decode_address(addr), 1, None))
        outputs.append(WalletOutputInfo(decode_address(addr), 1000, None))
        outputs.append(WalletOutputInfo(decode_address(addr), 6400-1002, None))
        tx_fund0 = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, manager.tx_storage)
        tx_fund0.weight = 1
        tx_fund0.parents = manager.get_new_tx_parents()
        tx_fund0.timestamp = int(self.clock.seconds())
        manager.cpu_mining_service.resolve(tx_fund0)
        self.assertTrue(manager.propagate_tx(tx_fund0))

        def do_step(tx_fund: Transaction) -> Transaction:
            inputs = [WalletInputInfo(tx_fund.hash, 0, manager.wallet.get_private_key(addr))]
            outputs = [WalletOutputInfo(decode_address(addr), 1, None)]
            tx1 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx_fund.timestamp+1)
            tx1.weight = 1
            tx1.parents = manager.get_new_tx_parents(tx1.timestamp)
            manager.cpu_mining_service.resolve(tx1)
            self.assertTrue(manager.propagate_tx(tx1))

            inputs = []
            inputs.append(WalletInputInfo(tx1.hash, 0, manager.wallet.get_private_key(addr)))
            inputs.append(WalletInputInfo(tx_fund.hash, 1, manager.wallet.get_private_key(addr)))
            outputs = [WalletOutputInfo(decode_address(addr), 2, None)]
            tx2 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx1.timestamp+1)
            tx2.weight = 1.1
            tx2.parents = manager.get_new_tx_parents(tx2.timestamp)
            manager.cpu_mining_service.resolve(tx2)
            self.assertTrue(manager.propagate_tx(tx2))

            inputs = []
            inputs.append(WalletInputInfo(tx_fund.hash, 2, manager.wallet.get_private_key(addr)))
            inputs.append(WalletInputInfo(tx_fund.hash, 1, manager.wallet.get_private_key(addr)))
            outputs = [WalletOutputInfo(decode_address(addr), tx_fund.outputs[2].value+1, None)]
            tx3 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx_fund.timestamp+1)
            tx3.weight = 1
            tx3.parents = manager.get_new_tx_parents(tx3.timestamp)
            manager.cpu_mining_service.resolve(tx3)
            self.assertTrue(manager.propagate_tx(tx3))

            inputs = []
            inputs.append(WalletInputInfo(tx_fund.hash, 0, manager.wallet.get_private_key(addr)))
            inputs.append(WalletInputInfo(tx_fund.hash, 2, manager.wallet.get_private_key(addr)))
            outputs = [WalletOutputInfo(decode_address(addr), tx_fund.outputs[2].value+1, None)]
            tx4 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx_fund.timestamp+1)
            tx4.weight = tx1.weight + tx2.weight + 0.1
            tx4.parents = manager.get_new_tx_parents(tx4.timestamp)
            manager.cpu_mining_service.resolve(tx4)
            self.assertTrue(manager.propagate_tx(tx4))

            inputs = []
            inputs.append(WalletInputInfo(tx3.hash, 0, manager.wallet.get_private_key(addr)))
            inputs.append(WalletInputInfo(tx4.hash, 0, manager.wallet.get_private_key(addr)))
            outputs = []
            outputs.append(WalletOutputInfo(decode_address(addr), 1, None))
            outputs.append(WalletOutputInfo(decode_address(addr), 1, None))
            outputs.append(WalletOutputInfo(decode_address(addr), 2*tx_fund.outputs[2].value, None))
            tx5: Transaction = manager.wallet.prepare_transaction(Transaction, inputs, outputs, tx4.timestamp+1)
            tx5.weight = 1
            tx5.parents = manager.get_new_tx_parents(tx5.timestamp)
            manager.cpu_mining_service.resolve(tx5)
            self.assertTrue(manager.propagate_tx(tx5))
            return tx5

        tx = tx_fund0
        N = 10
        for _ in range(N):
            tx = do_step(tx)

        self.run_to_completion()
        block = add_new_block(manager)
        self.assertIn(tx.hash, block.parents)

        meta = tx.get_metadata()
        self.assertEqual(meta.conflict_with, None)
        self.assertEqual(meta.voided_by, None)
        self.assertEqual(tx.outputs[2].value, 1000*2**N)

        self.assertConsensusValid(manager)
