import hashlib
from typing import Any, cast

from hathor.conf import HathorSettings
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.exception import (
    BlueprintDoesNotExist,
    NanoContractDoesNotExist,
    NCFail,
    NCInvalidPubKey,
    NCInvalidSignature,
    NCMethodNotFound,
    NCSerializationError,
)
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.types import NCAction, NCActionType, TokenUid
from hathor.simulator.trigger import StopAfterMinimumBalance, StopAfterNMinedBlocks
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.headers import NanoHeader
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.types import VertexId
from hathor.wallet.base_wallet import WalletOutputInfo
from tests.simulation.base import SimulatorTestCase
from tests.utils import add_custom_tx, create_tokens, gen_custom_base_tx

settings = HathorSettings()


class MyBlueprint(Blueprint):
    total: int
    token_uid: TokenUid
    counter: int

    @public
    def initialize(self, ctx: Context, token_uid: TokenUid) -> None:
        self.total = 0
        self.counter = 0
        self.token_uid = token_uid

    def _get_action(self, ctx: Context) -> NCAction:
        if len(ctx.actions) != 1:
            raise NCFail('only one action allowed')
        if self.token_uid not in ctx.actions:
            raise NCFail('invalid token')
        action = ctx.actions[self.token_uid]
        if action.token_uid != self.token_uid:
            raise NCFail('invalid token')
        return action

    @public
    def nop(self, ctx: Context, a: int) -> None:
        self.counter += 1

    @public
    def deposit(self, ctx: Context) -> None:
        self.counter += 1
        action = self._get_action(ctx)
        if action.type != NCActionType.DEPOSIT:
            raise NCFail('deposits only')
        self.total += action.amount

    @public
    def withdraw(self, ctx: Context) -> None:
        self.counter += 1
        action = self._get_action(ctx)
        if action.type != NCActionType.WITHDRAWAL:
            raise NCFail('withdrawal only')
        self.total -= action.amount

    @public
    def fail_on_zero(self, ctx: Context) -> None:
        if self.counter == 0:
            raise NCFail('counter is zero')


class NCConsensusTestCase(SimulatorTestCase):
    __test__ = True

    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })

        self.manager = self.simulator.create_peer()
        self.manager.allow_mining_without_peers()
        self.manager.tx_storage.nc_catalog = self.catalog

        self.wallet = self.manager.wallet

        self.miner = self.simulator.create_miner(self.manager, hashpower=100e6)
        self.miner.start()

        self.token_uid = TokenUid(b'\0')
        trigger = StopAfterMinimumBalance(self.wallet, self.token_uid, 1)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

    def assertNoBlocksVoided(self):
        for blk in self.manager.tx_storage.get_all_transactions():
            if not blk.is_block:
                continue
            meta = blk.get_metadata()
            self.assertIsNone(meta.voided_by)

    def _gen_nc_tx(
        self,
        nc_id: VertexId,
        nc_method: str,
        nc_args: list[Any],
        nc: BaseTransaction | None = None,
        *,
        address: str | None = None,
        nc_actions: list[NanoHeaderAction] | None = None,
        is_custom_token: bool = False,
    ) -> Transaction:
        method_parser = NCMethodParser(getattr(MyBlueprint, nc_method))

        if nc is None:
            nc = Transaction()
        assert isinstance(nc, Transaction)

        nc_args_bytes = method_parser.serialize_args(nc_args)

        if address is None:
            address = self.wallet.get_unused_address()
        privkey = self.wallet.get_private_key(address)
        pubkey_bytes = privkey.sec()

        nano_header = NanoHeader(
            tx=nc,
            nc_version=1,
            nc_id=nc_id,
            nc_method=nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_pubkey=pubkey_bytes,
            nc_signature=b'',
            nc_actions=nc_actions or [],
        )
        nc.headers.append(nano_header)

        if is_custom_token:
            nc.tokens = [self.token_uid]

        data = nc.get_sighash_all()
        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        nano_header.nc_signature = privkey.sign(data_hash)

        self._finish_preparing_tx(nc)
        self.manager.reactor.advance(10)
        return nc

    def _finish_preparing_tx(self, tx):
        tx.timestamp = int(self.manager.reactor.seconds())
        tx.parents = self.manager.get_new_tx_parents()
        tx.weight = self.manager.daa.minimum_tx_weight(tx)
        return tx

    def test_nc_consensus_unknown_blueprint(self):
        nc = self._gen_nc_tx(b'y' * 32, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.on_new_tx(nc, fails_silently=False)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, BlueprintDoesNotExist)

    def test_nc_consensus_unknown_contract_1(self):
        nc = self._gen_nc_tx(b'y' * 32, 'deposit', [])
        self.manager.cpu_mining_service.resolve(nc)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.on_new_tx(nc, fails_silently=False)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, NanoContractDoesNotExist)

    def test_nc_consensus_unknown_contract_2(self):
        v = list(self.manager.tx_storage.get_all_transactions())
        nc = self._gen_nc_tx(v[0].hash, 'deposit', [])
        self.manager.cpu_mining_service.resolve(nc)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.on_new_tx(nc, fails_silently=False)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, NanoContractDoesNotExist)

    def test_nc_consensus_unknown_contract_3(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        tx1 = self._gen_nc_tx(nc.hash, 'nop', [1])
        self.manager.cpu_mining_service.resolve(tx1)
        self.manager.on_new_tx(tx1, fails_silently=False)

        # tx2 points to tx1 as if it were a contract, which makes it an invalid transaction.
        tx2 = self._gen_nc_tx(tx1.hash, 'nop', [1])
        self.manager.cpu_mining_service.resolve(tx2)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.on_new_tx(tx2, fails_silently=False)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, NanoContractDoesNotExist)

    def test_nc_consensus_unknown_method(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        tx = self._gen_nc_tx(nc.hash, 'deposit', [])
        nano_header = tx.get_nano_header()
        nano_header.nc_method = 'unknown'
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.on_new_tx(tx, fails_silently=False)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, NCMethodNotFound)

    def test_nc_consensus_invalid_args(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        tx = self._gen_nc_tx(nc.hash, 'nop', [1])
        nano_header = tx.get_nano_header()
        nano_header.nc_method = 'deposit'
        tx.weight = self.manager.daa.minimum_tx_weight(tx)
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.on_new_tx(tx, fails_silently=False)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, NCSerializationError)

    def _run_invalid_signature(self, attr, value, cause=NCInvalidSignature):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        tx = self._gen_nc_tx(nc.hash, 'deposit', [])
        nano_header = tx.get_nano_header()
        self.assertNotEqual(getattr(nano_header, attr), value)
        setattr(nano_header, attr, value)
        tx.weight = self.manager.daa.minimum_tx_weight(tx)
        self.manager.cpu_mining_service.resolve(tx)

        tx.clear_sighash_cache()
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.on_new_tx(tx, fails_silently=False)
        exc = cm.exception
        self.assertIsInstance(exc.__cause__, cause)

    def test_nc_consensus_invalid_signature_change_nc_method(self):
        self._run_invalid_signature('nc_method', 'withdraw')

    def test_nc_consensus_invalid_signature_change_nc_id(self):
        self._run_invalid_signature('nc_id', b'y' * 32)

    def test_nc_consensus_invalid_signature_change_nc_args_bytes(self):
        self._run_invalid_signature('nc_args_bytes', b'x')

    def test_nc_consensus_invalid_signature_change_nc_pubkey_1(self):
        self._run_invalid_signature('nc_pubkey', b'x', cause=NCInvalidPubKey)

    def test_nc_consensus_invalid_signature_change_nc_pubkey_2(self):
        privkey = self.wallet.get_key_at_index(100)
        pubkey_bytes = privkey.sec()
        self._run_invalid_signature('nc_pubkey', pubkey_bytes)

    def test_nc_consensus_execution_fails(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        tx = self._gen_nc_tx(nc.hash, 'deposit', [])
        self.manager.cpu_mining_service.resolve(tx)
        self.manager.on_new_tx(tx, fails_silently=False)
        self.assertIsNone(tx.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta = tx.get_metadata()
        self.assertIsNotNone(meta.first_block)
        self.assertEqual(meta.voided_by, {tx.hash, settings.NC_EXECUTION_FAIL_ID})

        # add another block that confirms tx
        self._add_new_block(tx_parents=[
            tx.hash,
            tx.parents[0],
        ])

        self.assertNoBlocksVoided()

    def test_nc_consensus_success_custom_token(self):
        token_creation_tx = create_tokens(self.manager, mint_amount=100, use_genesis=False, propagate=False)
        self._finish_preparing_tx(token_creation_tx)
        token_creation_tx.timestamp += 1
        self.manager.cpu_mining_service.resolve(token_creation_tx)
        self.manager.on_new_tx(token_creation_tx, fails_silently=False)

        self.token_uid = token_creation_tx.hash
        self.test_nc_consensus_success(is_custom_token=True)

    def test_nc_consensus_success(self, *, is_custom_token: bool = False) -> None:
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        nc_id = nc.hash

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(14400, trigger=trigger))
        nc_loaded = self.manager.tx_storage.get_transaction(nc_id)
        nc_loaded_meta = nc_loaded.get_metadata()
        self.assertIsNotNone(nc_loaded_meta.first_block)
        self.assertIsNone(nc_loaded_meta.voided_by)

        block_initialize = self.manager.tx_storage.get_best_block()

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(nc_storage.get('token_uid'), self.token_uid)

        # Make a deposit.

        _inputs, deposit_amount = self.wallet.get_inputs_from_amount(
            1, self.manager.tx_storage, token_uid=self.token_uid
        )
        tx = self.wallet.prepare_transaction(Transaction, _inputs, [])
        tx = self._gen_nc_tx(nc_id, 'deposit', [], nc=tx, is_custom_token=is_custom_token, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.DEPOSIT,
                token_index=1 if is_custom_token else 0,
                amount=deposit_amount,
            )
        ])
        self.manager.cpu_mining_service.resolve(tx)
        self.manager.on_new_tx(tx, fails_silently=False)
        self.assertIsNone(tx.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta = tx.get_metadata()
        self.assertIsNotNone(meta.first_block)
        self.assertIsNone(meta.voided_by)

        block_deposit = self.manager.tx_storage.get_best_block()

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(deposit_amount, nc_storage.get_balance(self.token_uid))

        # Make a withdrawal of 1 HTR.

        _output_token_index = 0
        _tokens = []
        if is_custom_token:
            _tokens.append(self.token_uid)
            _output_token_index = 1

        tx2 = Transaction(outputs=[TxOutput(1, b'', _output_token_index)])
        tx2.tokens = _tokens
        tx2 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx2, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.WITHDRAWAL,
                token_index=1 if is_custom_token else 0,
                amount=1,
            )
        ])
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.on_new_tx(tx2, fails_silently=False)
        self.assertIsNone(tx2.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta2 = tx2.get_metadata()
        self.assertIsNotNone(meta2.first_block)
        self.assertIsNone(meta2.voided_by)

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(deposit_amount - 1, nc_storage.get_balance(self.token_uid))

        # Make a withdrawal of the remainder.

        tx3 = Transaction(outputs=[TxOutput(deposit_amount - 2, b'', _output_token_index)])
        tx3.tokens = _tokens
        tx3 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx3, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.WITHDRAWAL,
                token_index=1 if is_custom_token else 0,
                amount=deposit_amount - 2,
            )
        ])
        self.manager.cpu_mining_service.resolve(tx3)
        self.manager.on_new_tx(tx3, fails_silently=False)
        self.assertIsNone(tx3.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta3 = tx3.get_metadata()
        self.assertIsNotNone(meta3.first_block)
        self.assertIsNone(meta3.voided_by)

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(1, nc_storage.get_balance(self.token_uid))

        # Try to withdraw more than available, so it fails.

        _output_token_index = 0
        _tokens = []
        if is_custom_token:
            _tokens.append(self.token_uid)
            _output_token_index = 1

        tx4 = Transaction(outputs=[TxOutput(2, b'', _output_token_index)])
        tx4.tokens = _tokens
        tx4 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx4, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.WITHDRAWAL,
                token_index=1 if is_custom_token else 0,
                amount=2,
            )
        ])
        self.manager.cpu_mining_service.resolve(tx4)
        self.manager.on_new_tx(tx4, fails_silently=False)
        self.assertIsNone(tx4.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta4 = tx4.get_metadata()
        self.assertIsNotNone(meta4.first_block)
        self.assertEqual(meta4.voided_by, {tx4.hash, settings.NC_EXECUTION_FAIL_ID})

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(1, nc_storage.get_balance(self.token_uid))

        self.assertNoBlocksVoided()

        # Check balance at different blocks

        nc_storage = self.manager.get_nc_storage(block_initialize, nc_id)
        self.assertEqual(0, nc_storage.get_balance(self.token_uid))

        nc_storage = self.manager.get_nc_storage(block_deposit, nc_id)
        self.assertEqual(deposit_amount, nc_storage.get_balance(self.token_uid))

    def test_nc_consensus_failure_voided_by_propagation(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        # Find some blocks.
        self.assertTrue(self.simulator.run(600))

        # tx1 is a NanoContract transaction and will fail execution.
        address = self.wallet.get_unused_address_bytes()
        _outputs = [
            WalletOutputInfo(address, 1, None),
            WalletOutputInfo(address, 1, None),
        ]
        tx1 = self.wallet.prepare_transaction_compute_inputs(Transaction, _outputs, self.manager.tx_storage)
        tx1 = self._gen_nc_tx(nc.hash, 'deposit', [], nc=tx1)
        self.manager.cpu_mining_service.resolve(tx1)
        self.manager.on_new_tx(tx1, fails_silently=False)
        self.assertIsNone(tx1.get_metadata().voided_by)

        # add tx21 spending tx1 in mempool before tx1 has been executed
        tx21 = add_custom_tx(self.manager, tx_inputs=[(tx1, 0)])
        tx21_meta = tx21.get_metadata()
        self.assertIsNone(tx21_meta.voided_by)

        # add tx22 with tx1 as parent in mempool before tx1 has been executed
        address = self.wallet.get_unused_address_bytes()
        _outputs = [
            WalletOutputInfo(address, 1, None),
        ]
        tx22 = self.wallet.prepare_transaction_compute_inputs(Transaction, _outputs, self.manager.tx_storage)
        self._finish_preparing_tx(tx22)
        tx22.parents[0] = tx1.hash
        self.manager.cpu_mining_service.resolve(tx22)
        self.manager.on_new_tx(tx22, fails_silently=False)
        tx22_meta = tx22.get_metadata()
        self.assertIsNone(tx22_meta.voided_by)

        # executes tx1 and asserts the final state
        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        # confirm that tx1 failed execution.
        meta = tx1.get_metadata()
        self.assertIsNotNone(meta.first_block)
        self.assertEqual(meta.voided_by, {settings.NC_EXECUTION_FAIL_ID, tx1.hash})

        # tx21 must be voided because it spends an input from tx and tx failed execution.
        self.assertEqual(tx21_meta.voided_by, {tx1.hash})

        # tx22 will not be voided because it just verifies tx1
        tx22_meta = tx22.get_metadata()
        self.assertIsNone(tx22_meta.voided_by)

        # add tx31 spending tx1 in mempool after tx1 has been executed
        tx31 = add_custom_tx(self.manager, tx_inputs=[(tx1, 1)])
        tx31_meta = tx31.get_metadata()
        self.assertEqual(tx31_meta.voided_by, {tx1.hash})

        # add tx32 spending tx22 in mempool after tx1 has been executed
        tx32 = add_custom_tx(self.manager, tx_inputs=[(tx22, 0)])
        self.assertIn(tx1.hash, tx32.parents)
        tx32_meta = tx32.get_metadata()
        self.assertIsNone(tx32_meta.voided_by)

        # add tx33 in mempool, it spends tx1 with conflict after tx1 has been executed
        tx33 = add_custom_tx(self.manager, tx_inputs=[(tx1, 0)])
        tx33_meta = tx33.get_metadata()
        self.assertEqual(tx33_meta.voided_by, {tx1.hash, tx33.hash})

        # confirm that tx1 inputs are unspent (i.e., they are still UTXOs).
        tx1in = tx1.inputs[0]
        tx1_spent_tx = self.manager.tx_storage.get_transaction(tx1in.tx_id)
        tx1_spent_idx = tx1in.index
        tx34 = add_custom_tx(self.manager, tx_inputs=[(tx1_spent_tx, tx1_spent_idx)])
        tx34_meta = tx34.get_metadata()
        self.assertIsNone(tx34_meta.voided_by)

        self.assertNoBlocksVoided()

    def test_nc_consensus_chain_fail(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        # Find some blocks.
        self.assertTrue(self.simulator.run(600))

        # tx1 is a NanoContract transaction and will fail execution.
        address = self.wallet.get_unused_address_bytes()
        _outputs = [
            WalletOutputInfo(address, 1, None),
            WalletOutputInfo(address, 1, None),
        ]
        tx1 = self.wallet.prepare_transaction_compute_inputs(Transaction, _outputs, self.manager.tx_storage)
        tx1 = self._gen_nc_tx(nc.hash, 'deposit', [], nc=tx1)
        self.manager.cpu_mining_service.resolve(tx1)

        # tx2 is a NanoContract transaction independent of tx1
        tx2 = self._gen_nc_tx(nc.hash, 'nop', [1])
        self.manager.cpu_mining_service.resolve(tx2)

        # propagate both tx1 and tx2
        self.assertTrue(self.manager.on_new_tx(tx1, fails_silently=False))
        self.assertTrue(self.manager.on_new_tx(tx2, fails_silently=False))

        # tx3 is a NanoContract transaction that has tx1 as parent
        tx3 = self._gen_nc_tx(nc.hash, 'nop', [1])
        if tx1.hash not in tx3.parents:
            tx3.parents[0] = tx1.hash
        tx3.timestamp += 1
        self.manager.cpu_mining_service.resolve(tx3)
        self.assertTrue(self.manager.on_new_tx(tx3, fails_silently=False))

        # tx4 is a NanoContract transaction that spents tx1 output.
        tx4 = gen_custom_base_tx(self.manager, tx_inputs=[(tx1, 0)])
        self._gen_nc_tx(nc.hash, 'nop', [1], nc=tx4)
        tx4.timestamp += 2
        # self.assertNotIn(tx1.hash, tx4.parents)
        self.manager.cpu_mining_service.resolve(tx4)
        self.assertTrue(self.manager.on_new_tx(tx4, fails_silently=False))

        # tx5 is a NanoContract transaction that spents tx4 output.
        tx5 = gen_custom_base_tx(self.manager, tx_inputs=[(tx4, 0)])
        self._gen_nc_tx(nc.hash, 'nop', [1], nc=tx5)
        tx5.timestamp += 3
        # self.assertNotIn(tx1.hash, tx5.parents)
        self.manager.cpu_mining_service.resolve(tx5)
        self.assertTrue(self.manager.on_new_tx(tx5, fails_silently=False))

        # execute all transactions.
        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        # assert state after execution (tx1 fails, tx2 executes)
        self.assertEqual(tx1.get_metadata().voided_by, {tx1.hash, settings.NC_EXECUTION_FAIL_ID})
        self.assertIsNone(tx2.get_metadata().voided_by)
        self.assertIsNone(tx3.get_metadata().voided_by)
        self.assertEqual(tx4.get_metadata().voided_by, {tx1.hash})
        self.assertEqual(tx5.get_metadata().voided_by, {tx1.hash})

        nc_storage = self.manager.get_best_block_nc_storage(nc.hash)
        self.assertEqual(2, nc_storage.get('counter'))

    def _add_new_block(self,
                       *,
                       parents: list[VertexId] | None = None,
                       tx_parents: list[VertexId] | None = None,
                       parent_block_hash: VertexId | None = None) -> Block:
        if parents:
            assert len(parents) == 3
            assert parent_block_hash is None
            assert tx_parents is None
            parent_block_hash = parents[0]
            tx_parents = parents[1:]
        block = self.manager.generate_mining_block(parent_block_hash=parent_block_hash)
        if tx_parents is not None:
            assert len(tx_parents) == 2
            block.parents[1] = tx_parents[0]
            block.parents[2] = tx_parents[1]
        self.manager.cpu_mining_service.resolve(block)
        self.manager.propagate_tx(block, fails_silently=False)
        return block

    def test_nc_consensus_reorg(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        nc_id = nc.hash

        # Find some blocks.
        self.assertTrue(self.simulator.run(600))

        # Generate two addresses.
        address1 = self.wallet.get_address(self.wallet.get_key_at_index(0))
        address2 = self.wallet.get_address(self.wallet.get_key_at_index(1))
        self.assertNotEqual(address1, address2)

        # Prepare three sibling transactions.
        _inputs, deposit_amount_1 = self.wallet.get_inputs_from_amount(1, self.manager.tx_storage)
        tx1 = self.wallet.prepare_transaction(Transaction, _inputs, [])
        tx1 = self._gen_nc_tx(nc_id, 'deposit', [], nc=tx1, address=address1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.DEPOSIT,
                token_index=0,
                amount=deposit_amount_1,
            )
        ])
        self.manager.cpu_mining_service.resolve(tx1)

        self.manager.reactor.advance(10)

        withdrawal_amount_1 = 123
        tx11 = Transaction(outputs=[TxOutput(withdrawal_amount_1, b'', 0)])
        tx11 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx11, address=address1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.WITHDRAWAL,
                token_index=0,
                amount=withdrawal_amount_1,
            )
        ])
        tx11.weight += 1
        self.manager.cpu_mining_service.resolve(tx11)

        self.manager.reactor.advance(10)

        _inputs, deposit_amount_2 = self.wallet.get_inputs_from_amount(3, self.manager.tx_storage)
        tx2 = self.wallet.prepare_transaction(Transaction, _inputs, [])
        tx2 = self._gen_nc_tx(nc_id, 'deposit', [], nc=tx2, address=address2, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.DEPOSIT,
                token_index=0,
                amount=deposit_amount_2,
            )
        ])
        tx2.weight += 1
        self.manager.cpu_mining_service.resolve(tx2)

        # Propagate tx1, tx2, and tx11.
        self.manager.on_new_tx(tx1, fails_silently=False)
        self.manager.on_new_tx(tx2, fails_silently=False)
        self.manager.on_new_tx(tx11, fails_silently=False)

        # Add a block that executes tx1 and tx11 (but not tx2).
        blk10 = self._add_new_block(tx_parents=[
            tx1.hash,
            tx11.hash,
        ])
        blk_base_hash = blk10.parents[0]

        self.assertEqual(tx1.get_metadata().first_block, blk10.hash)
        self.assertIsNone(tx2.get_metadata().first_block)
        self.assertEqual(tx11.get_metadata().first_block, blk10.hash)

        self.assertIsNone(tx1.get_metadata().voided_by)
        self.assertIsNone(tx2.get_metadata().voided_by)
        self.assertIsNone(tx11.get_metadata().voided_by)

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(deposit_amount_1 - withdrawal_amount_1, nc_storage.get_balance(self.token_uid))

        # Cause a reorg that will execute tx2 and tx11 (but not tx1).
        blk20 = self._add_new_block(parents=[
            blk_base_hash,
            tx2.hash,
            tx11.hash,
        ])
        self._add_new_block(parents=[
            blk20.hash,
            blk20.parents[1],
            blk20.parents[2],
        ])

        self.assertIsNone(tx1.get_metadata().first_block)
        self.assertEqual(tx2.get_metadata().first_block, blk20.hash)
        self.assertEqual(tx11.get_metadata().first_block, blk20.hash)

        self.assertIsNone(tx1.get_metadata().voided_by)
        self.assertIsNone(tx2.get_metadata().voided_by)
        self.assertEqual(tx11.get_metadata().voided_by, {tx11.hash, settings.NC_EXECUTION_FAIL_ID})

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(deposit_amount_2, nc_storage.get_balance(self.token_uid))

    def test_nc_consensus_reorg_fail_before_reorg(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        nc_id = nc.hash

        # Find some blocks.
        self.assertTrue(self.simulator.run(600))

        # Generate two addresses.
        address1 = self.wallet.get_address(self.wallet.get_key_at_index(0))
        address2 = self.wallet.get_address(self.wallet.get_key_at_index(1))
        self.assertNotEqual(address1, address2)

        # Prepare three sibling transactions.
        _inputs, deposit_amount_2 = self.wallet.get_inputs_from_amount(3, self.manager.tx_storage)
        tx2 = self.wallet.prepare_transaction(Transaction, _inputs, [])
        tx2 = self._gen_nc_tx(nc_id, 'deposit', [], nc=tx2, address=address2, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.DEPOSIT,
                token_index=0,
                amount=deposit_amount_2,
            )
        ])
        self.manager.cpu_mining_service.resolve(tx2)

        self.manager.reactor.advance(10)

        withdrawal_amount_1 = 123
        tx11 = Transaction(outputs=[TxOutput(withdrawal_amount_1, b'', 0)])
        tx11 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx11, address=address1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.WITHDRAWAL,
                token_index=0,
                amount=withdrawal_amount_1,
            )
        ])
        tx11.weight += 1
        self.manager.cpu_mining_service.resolve(tx11)

        self.manager.reactor.advance(10)

        _inputs, deposit_amount_1 = self.wallet.get_inputs_from_amount(1, self.manager.tx_storage)
        tx1 = self.wallet.prepare_transaction(Transaction, _inputs, [])
        tx1 = self._gen_nc_tx(nc_id, 'deposit', [], nc=tx1, address=address1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.DEPOSIT,
                token_index=0,
                amount=deposit_amount_1,
            )
        ])
        tx1.weight += 2
        self.manager.cpu_mining_service.resolve(tx1)

        # Propagate tx1, tx2, and tx11.
        self.manager.on_new_tx(tx1, fails_silently=False)
        self.manager.on_new_tx(tx2, fails_silently=False)
        self.manager.on_new_tx(tx11, fails_silently=False)

        # Add a block that executes tx1 and tx11 (but not tx2).
        blk10 = self._add_new_block(tx_parents=[
            tx1.hash,
            tx11.hash,
        ])
        blk_base_hash = blk10.parents[0]

        self.assertEqual(tx1.get_metadata().first_block, blk10.hash)
        self.assertIsNone(tx2.get_metadata().first_block)
        self.assertEqual(tx11.get_metadata().first_block, blk10.hash)

        self.assertIsNone(tx1.get_metadata().voided_by)
        self.assertIsNone(tx2.get_metadata().voided_by)
        self.assertEqual(tx11.get_metadata().voided_by, {tx11.hash, settings.NC_EXECUTION_FAIL_ID})

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(deposit_amount_1, nc_storage.get_balance(self.token_uid))

        # Cause a reorg that will execute tx2 and tx11 (but not tx1).
        blk20 = self._add_new_block(parents=[
            blk_base_hash,
            tx2.hash,
            tx11.hash,
        ])
        self._add_new_block(parents=[
            blk20.hash,
            blk20.parents[1],
            blk20.parents[2],
        ])

        self.assertIsNone(tx1.get_metadata().first_block)
        self.assertEqual(tx2.get_metadata().first_block, blk20.hash)
        self.assertEqual(tx11.get_metadata().first_block, blk20.hash)

        self.assertIsNone(tx1.get_metadata().voided_by)
        self.assertIsNone(tx2.get_metadata().voided_by)
        self.assertIsNone(tx11.get_metadata().voided_by)

        nc_storage = self.manager.get_best_block_nc_storage(nc_id)
        self.assertEqual(deposit_amount_2 - withdrawal_amount_1, nc_storage.get_balance(self.token_uid))

    def _prepare_nc_consensus_conflict(self, *, conflict_with_nano: bool) -> tuple[Transaction, ...]:
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        # Find some blocks.
        self.assertTrue(self.simulator.run(600))

        # tx0 is a regular transaction with one output
        address = self.wallet.get_unused_address_bytes()
        _outputs = [
            WalletOutputInfo(address, 10, None),
        ]
        tx0 = self.wallet.prepare_transaction_compute_inputs(Transaction, _outputs, self.manager.tx_storage)
        self._finish_preparing_tx(tx0)
        self.manager.cpu_mining_service.resolve(tx0)
        self.manager.reactor.advance(60)

        # tx1 is a NanoContract transaction and will fail execution.
        tx1 = gen_custom_base_tx(self.manager, tx_inputs=[(tx0, 0)])
        self.assertEqual(len(tx1.outputs), 1)
        tx1.outputs[0].value = 3
        tx1 = self._gen_nc_tx(nc.hash, 'deposit', [], nc=tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.DEPOSIT,
                token_index=0,
                amount=tx0.outputs[0].value - 3,
            )
        ])
        self.manager.cpu_mining_service.resolve(tx1)

        # tx2 is a NanoContract transaction that spends tx1.
        tx2 = gen_custom_base_tx(self.manager, tx_inputs=[(tx1, 0)])
        tx2 = self._gen_nc_tx(nc.hash, 'nop', [1], nc=tx2)
        self.manager.cpu_mining_service.resolve(tx2)

        # tx1b is in conflict with tx1
        if conflict_with_nano:
            tx1b = gen_custom_base_tx(self.manager, tx_inputs=[(tx0, 0)])
            self._gen_nc_tx(nc.hash, 'nop', [1], nc=tx1b)
        else:
            tx1b = gen_custom_base_tx(self.manager, tx_inputs=[(tx0, 0)])
        self.manager.cpu_mining_service.resolve(tx1b)

        # propagate both tx1 and tx2
        self.assertTrue(self.manager.on_new_tx(tx0, fails_silently=False))
        self.assertTrue(self.manager.on_new_tx(tx1, fails_silently=False))
        self.assertTrue(self.manager.on_new_tx(tx1b, fails_silently=False))
        self.assertTrue(self.manager.on_new_tx(tx2, fails_silently=False))

        return cast(tuple[Transaction, ...], (tx0, tx1, tx1b, tx2))

    def _run_nc_consensus_conflict_block_voided_1(self, *, conflict_with_nano: bool) -> None:
        tx0, tx1, tx1b, tx2 = self._prepare_nc_consensus_conflict(conflict_with_nano=conflict_with_nano)

        # this block must be voided because it confirms both tx1 and tx1b.
        block = self.manager.generate_mining_block()
        block.parents = [
            block.parents[0],
            tx1.hash,
            tx1b.hash,
        ]
        self.manager.cpu_mining_service.resolve(block)
        self.assertTrue(self.manager.on_new_tx(block, fails_silently=False))
        self.assertTrue(block.get_metadata().voided_by)

    def test_nc_consensus_conflict_block_voided_1(self) -> None:
        self._run_nc_consensus_conflict_block_voided_1(conflict_with_nano=False)

    def test_nc_consensus_nano_conflict_block_voided_1(self) -> None:
        self._run_nc_consensus_conflict_block_voided_1(conflict_with_nano=True)

    def _run_nc_consensus_conflict_block_voided_2(self, *, conflict_with_nano: bool) -> None:
        tx0, tx1, tx1b, tx2 = self._prepare_nc_consensus_conflict(conflict_with_nano=conflict_with_nano)

        # this block will be executed.
        b0 = self.manager.generate_mining_block()
        b0.parents = [
            b0.parents[0],
            tx1.hash,
            tx2.hash,
        ]
        self.manager.cpu_mining_service.resolve(b0)
        self.assertTrue(self.manager.on_new_tx(b0, fails_silently=False))
        self.assertIsNone(b0.get_metadata().voided_by)

        # this block will be voided because it confirms tx1b.
        b1 = self.manager.generate_mining_block()
        b1.parents = [
            b1.parents[0],
            tx1b.hash,
            tx1b.parents[0],
        ]
        self.manager.cpu_mining_service.resolve(b1)
        self.assertTrue(self.manager.on_new_tx(b1, fails_silently=False))
        self.assertIsNotNone(b1.get_metadata().voided_by)

    def test_nc_consensus_conflict_block_voided_2(self) -> None:
        self._run_nc_consensus_conflict_block_voided_2(conflict_with_nano=False)

    def test_nc_consensus_nano_conflict_block_voided_2(self) -> None:
        self._run_nc_consensus_conflict_block_voided_2(conflict_with_nano=True)

    def _run_nc_consensus_conflict_block_executed_1(self, *, conflict_with_nano: bool) -> None:
        tx0, tx1, tx1b, tx2 = self._prepare_nc_consensus_conflict(conflict_with_nano=conflict_with_nano)

        # this block will be confirmed first.
        b0 = self.manager.generate_mining_block()
        b0.parents = [
            b0.parents[0],
            tx1.hash,
            tx2.hash,
        ]
        self.manager.cpu_mining_service.resolve(b0)

        # this block will cause a reorg.
        b1 = self.manager.generate_mining_block()
        b1.weight += 1
        b1.parents = [
            b1.parents[0],
            tx1.hash,
            tx2.hash,
        ]
        self.manager.cpu_mining_service.resolve(b1)

        self.assertTrue(self.manager.on_new_tx(b0, fails_silently=False))
        self.assertIsNone(b0.get_metadata().voided_by)
        self.assertTrue(self.manager.on_new_tx(b1, fails_silently=False))
        self.assertIsNotNone(b0.get_metadata().voided_by)
        self.assertIsNone(b1.get_metadata().voided_by)
        self.assertIsNone(tx1.get_metadata().voided_by)
        self.assertIsNone(tx2.get_metadata().voided_by)
        self.assertIsNotNone(tx1b.get_metadata().voided_by)

    def test_nc_consensus_conflict_block_executed_1(self) -> None:
        self._run_nc_consensus_conflict_block_executed_1(conflict_with_nano=False)

    def test_nc_consensus_nano_conflict_block_executed_1(self) -> None:
        self._run_nc_consensus_conflict_block_executed_1(conflict_with_nano=True)

    def _run_nc_consensus_conflict_block_executed_2(self, *, conflict_with_nano: bool) -> None:
        tx0, tx1, tx1b, tx2 = self._prepare_nc_consensus_conflict(conflict_with_nano=conflict_with_nano)

        # this block is executed.
        b0 = self.manager.generate_mining_block()
        b0.parents = [
            b0.parents[0],
            tx1b.hash,
            tx1b.parents[0],
        ]
        self.manager.cpu_mining_service.resolve(b0)

        # this block will cause a reorg.
        b1 = self.manager.generate_mining_block()
        b1.weight += 1
        b1.parents = [
            b1.parents[0],
            tx1.hash,
            tx2.hash,
        ]
        self.manager.cpu_mining_service.resolve(b1)

        self.assertTrue(self.manager.on_new_tx(b0, fails_silently=False))
        self.assertIsNone(b0.get_metadata().voided_by)
        self.assertIsNotNone(tx1.get_metadata().voided_by)
        self.assertIsNotNone(tx2.get_metadata().voided_by)
        self.assertIsNone(tx1b.get_metadata().voided_by)

        self.assertTrue(self.manager.on_new_tx(b1, fails_silently=False))
        self.assertIsNotNone(b0.get_metadata().voided_by)
        self.assertIsNone(b1.get_metadata().voided_by)
        self.assertIsNone(tx1.get_metadata().voided_by)
        self.assertIsNone(tx2.get_metadata().voided_by)
        self.assertIsNotNone(tx1b.get_metadata().voided_by)

    def test_nc_consensus_conflict_block_executed_2(self) -> None:
        self._run_nc_consensus_conflict_block_executed_2(conflict_with_nano=False)

    def test_nc_consensus_nano_conflict_block_executed_2(self) -> None:
        self._run_nc_consensus_conflict_block_executed_2(conflict_with_nano=True)

    def test_nc_consensus_voided_tx_at_mempool(self) -> None:
        dag_builder = self.get_dag_builder(self.manager)
        vertices = dag_builder.build_from_str(f'''
            blockchain genesis b[1..40]
            b30 < dummy

            tx1.nc_id = "{self.myblueprint_id.hex()}"
            tx1.nc_method = initialize("00")

            # tx2 will fail because it does not have a deposit
            tx2.nc_id = tx1
            tx2.nc_method = deposit()
            tx2.out[0] <<< tx3

            # tx3 will be voided because tx2 failed execution
            tx3.nc_id = tx1
            tx3.nc_method = nop(1)

            b31 --> tx1
            b32 --> tx2
            b33 --> tx3
        ''')

        for node, vertex in vertices.list:
            print()
            print(node.name)
            print()
            self.manager.on_new_tx(vertex, fails_silently=False)

        b31 = vertices.by_name['b31'].vertex
        b32 = vertices.by_name['b32'].vertex
        b33 = vertices.by_name['b33'].vertex

        self.assertIsInstance(b31, Block)
        self.assertIsInstance(b32, Block)
        self.assertIsInstance(b33, Block)
        self.assertIsNone(b31.get_metadata().voided_by)
        self.assertIsNone(b32.get_metadata().voided_by)
        self.assertIsNone(b33.get_metadata().voided_by)

        tx1 = vertices.by_name['tx1'].vertex
        tx2 = vertices.by_name['tx2'].vertex
        tx3 = vertices.by_name['tx3'].vertex

        meta1 = tx1.get_metadata()
        meta2 = tx2.get_metadata()
        meta3 = tx3.get_metadata()

        self.assertEqual(meta1.first_block, b31.hash)
        self.assertEqual(meta2.first_block, b32.hash)
        self.assertEqual(meta3.first_block, b33.hash)

        self.assertIsNone(meta1.voided_by)
        self.assertEqual(meta2.voided_by, {tx2.hash, self._settings.NC_EXECUTION_FAIL_ID})
        self.assertEqual(meta3.voided_by, {tx2.hash})

    def test_reexecute_fail_on_reorg_different_blocks(self) -> None:
        dag_builder = self.get_dag_builder(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..33]
            blockchain b31 a[32..34]
            b30 < dummy

            nc1.nc_id = "{self.myblueprint_id.hex()}"
            nc1.nc_method = initialize("00")

            # nc2 will fail because it does not have a deposit
            nc2.nc_id = nc1
            nc2.nc_method = deposit()

            # nc3 will be voided because nc2 failed execution
            nc3.nc_id = nc1
            nc3.nc_method = nop(1)
            nc2.out[0] <<< nc3

            nc1 <-- b31
            nc2 <-- b32
            nc3 <-- b33

            # a34 will generate a reorg, reexecuting nc2 (which fails again).
            # nc2 and nc3 are in different blocks.
            b33 < a32
            nc2 <-- a32
            nc3 <-- a33
        ''')

        b31, b32, b33 = artifacts.get_typed_vertices(['b31', 'b32', 'b33'], Block)
        a32, a33, a34 = artifacts.get_typed_vertices(['a32', 'a33', 'a34'], Block)
        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)

        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        found_b33 = False
        for node, vertex in artifacts.list:
            assert self.manager.on_new_tx(vertex, fails_silently=False)

            if node.name == 'b33':
                found_b33 = True
                assert b33.get_metadata().voided_by is None
                assert nc1.get_metadata().voided_by is None
                assert nc2.get_metadata().voided_by == {nc2.hash, self._settings.NC_EXECUTION_FAIL_ID}
                assert nc3.get_metadata().voided_by == {nc2.hash}

                assert nc1.get_metadata().first_block == b31.hash
                assert nc2.get_metadata().first_block == b32.hash
                assert nc3.get_metadata().first_block == b33.hash

                assert self.manager.get_nc_storage(b33, nc1.hash).get('counter') == 0

        assert found_b33
        assert b33.get_metadata().voided_by == {b33.hash}
        assert a34.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None
        assert nc2.get_metadata().voided_by == {nc2.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert nc3.get_metadata().voided_by == {nc2.hash}

        assert nc1.get_metadata().first_block == b31.hash
        assert nc2.get_metadata().first_block == a32.hash
        assert nc3.get_metadata().first_block == a33.hash

        assert self.manager.get_nc_storage(a33, nc1.hash).get('counter') == 0

    def test_reexecute_fail_on_reorg_same_block(self) -> None:
        dag_builder = self.get_dag_builder(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..33]
            blockchain b31 a[32..34]
            b30 < dummy

            nc1.nc_id = "{self.myblueprint_id.hex()}"
            nc1.nc_method = initialize("00")

            # nc2 will fail because it does not have a deposit
            nc2.nc_id = nc1
            nc2.nc_method = deposit()

            # nc3 will be voided because nc2 failed execution
            nc3.nc_id = nc1
            nc3.nc_method = nop(1)
            nc2.out[0] <<< nc3

            nc1 <-- b31
            nc2 <-- b32
            nc3 <-- b33

            # a34 will generate a reorg, reexecuting nc2 (which fails again).
            # nc2 and nc3 are in the same block.
            b33 < a32
            nc2 <-- nc3 <-- a33
        ''')

        b31, b32, b33 = artifacts.get_typed_vertices(['b31', 'b32', 'b33'], Block)
        a32, a33, a34 = artifacts.get_typed_vertices(['a32', 'a33', 'a34'], Block)
        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)

        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        found_b33 = False
        for node, vertex in artifacts.list:
            assert self.manager.on_new_tx(vertex, fails_silently=False)

            if node.name == 'b33':
                found_b33 = True
                assert b33.get_metadata().voided_by is None
                assert nc1.get_metadata().voided_by is None
                assert nc2.get_metadata().voided_by == {nc2.hash, self._settings.NC_EXECUTION_FAIL_ID}
                assert nc3.get_metadata().voided_by == {nc2.hash}

                assert nc1.get_metadata().first_block == b31.hash
                assert nc2.get_metadata().first_block == b32.hash
                assert nc3.get_metadata().first_block == b33.hash

                assert self.manager.get_nc_storage(b33, nc1.hash).get('counter') == 0

        assert found_b33
        assert b33.get_metadata().voided_by == {b33.hash}
        assert a34.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None
        assert nc2.get_metadata().voided_by == {nc2.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert nc3.get_metadata().voided_by == {nc2.hash}

        assert nc1.get_metadata().first_block == b31.hash
        assert nc2.get_metadata().first_block == a33.hash
        assert nc3.get_metadata().first_block == a33.hash

        assert self.manager.get_nc_storage(a33, nc1.hash).get('counter') == 0

    def test_reexecute_success_on_reorg_different_blocks(self) -> None:
        dag_builder = self.get_dag_builder(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..33]
            blockchain b31 a[32..34]
            b30 < dummy

            nc1.nc_id = "{self.myblueprint_id.hex()}"
            nc1.nc_method = initialize("00")

            # nc2 will fail because nc1.counter is 0
            nc2.nc_id = nc1
            nc2.nc_method = fail_on_zero()

            # nc3 will be voided because nc2 failed execution
            nc3.nc_id = nc1
            nc3.nc_method = nop(1)
            nc2.out[0] <<< nc3

            nc1 <-- b31
            nc2 <-- b32
            nc3 <-- b33

            # a34 will generate a reorg, reexecuting nc2.
            # this time it succeeds because nc4 in the new chain increments nc1.counter to 1, before nc2.
            # nc2 and nc3 are in different blocks.

            nc4.nc_id = nc1
            nc4.nc_method = nop(1)
            nc4 < nc2
            nc4 <-- a32

            b33 < a32
            nc2 <-- a32
            nc3 <-- a33
        ''')

        b31, b32, b33 = artifacts.get_typed_vertices(['b31', 'b32', 'b33'], Block)
        a32, a33, a34 = artifacts.get_typed_vertices(['a32', 'a33', 'a34'], Block)
        nc1, nc2, nc3, nc4 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3', 'nc4'], Transaction)

        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()
        assert nc4.is_nano_contract()

        found_b33 = False
        for node, vertex in artifacts.list:
            assert self.manager.on_new_tx(vertex, fails_silently=False)

            if node.name == 'b33':
                found_b33 = True
                assert b33.get_metadata().voided_by is None
                assert nc1.get_metadata().voided_by is None
                assert nc2.get_metadata().voided_by == {nc2.hash, self._settings.NC_EXECUTION_FAIL_ID}
                assert nc3.get_metadata().voided_by == {nc2.hash}
                assert nc4.get_metadata().voided_by is None

                assert nc1.get_metadata().first_block == b31.hash
                assert nc2.get_metadata().first_block == b32.hash
                assert nc3.get_metadata().first_block == b33.hash
                assert nc4.get_metadata().first_block is None

                assert self.manager.get_nc_storage(b33, nc1.hash).get('counter') == 0

        assert found_b33
        assert b33.get_metadata().voided_by == {b33.hash}
        assert a34.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None
        assert nc2.get_metadata().voided_by is None
        assert nc3.get_metadata().voided_by is None
        assert nc4.get_metadata().voided_by is None

        assert nc1.get_metadata().first_block == b31.hash
        assert nc2.get_metadata().first_block == a32.hash
        assert nc3.get_metadata().first_block == a33.hash
        assert nc4.get_metadata().first_block == a32.hash

        assert self.manager.get_nc_storage(a33, nc1.hash).get('counter') == 2  # increments by nc4 and nc3

    def test_reexecute_success_on_reorg_same_block(self) -> None:
        dag_builder = self.get_dag_builder(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..33]
            blockchain b31 a[32..34]
            b30 < dummy

            nc1.nc_id = "{self.myblueprint_id.hex()}"
            nc1.nc_method = initialize("00")

            # nc2 will fail because nc1.counter is 0
            nc2.nc_id = nc1
            nc2.nc_method = fail_on_zero()

            # nc3 will be voided because nc2 failed execution
            nc3.nc_id = nc1
            nc3.nc_method = nop(1)
            nc2.out[0] <<< nc3

            nc1 <-- b31
            nc2 <-- b32
            nc3 <-- b33

            # a34 will generate a reorg, reexecuting nc2.
            # this time it succeeds because nc4 in the new chain increments nc1.counter to 1, before nc2.
            # nc2 and nc3 are in different blocks.

            nc4.nc_id = nc1
            nc4.nc_method = nop(1)
            nc4 < nc2
            nc4 <-- a32

            b33 < a32
            nc2 <-- nc3 <-- a33
        ''')

        b31, b32, b33 = artifacts.get_typed_vertices(['b31', 'b32', 'b33'], Block)
        a32, a33, a34 = artifacts.get_typed_vertices(['a32', 'a33', 'a34'], Block)
        nc1, nc2, nc3, nc4 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3', 'nc4'], Transaction)

        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()
        assert nc4.is_nano_contract()

        found_b33 = False
        for node, vertex in artifacts.list:
            assert self.manager.on_new_tx(vertex, fails_silently=False)

            if node.name == 'b33':
                found_b33 = True
                assert b33.get_metadata().voided_by is None
                assert nc1.get_metadata().voided_by is None
                assert nc2.get_metadata().voided_by == {nc2.hash, self._settings.NC_EXECUTION_FAIL_ID}
                assert nc3.get_metadata().voided_by == {nc2.hash}
                assert nc4.get_metadata().voided_by is None

                assert nc1.get_metadata().first_block == b31.hash
                assert nc2.get_metadata().first_block == b32.hash
                assert nc3.get_metadata().first_block == b33.hash
                assert nc4.get_metadata().first_block is None

                assert self.manager.get_nc_storage(b33, nc1.hash).get('counter') == 0

        assert found_b33
        assert b33.get_metadata().voided_by == {b33.hash}
        assert a34.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None
        assert nc2.get_metadata().voided_by is None
        assert nc3.get_metadata().voided_by is None
        assert nc4.get_metadata().voided_by is None

        assert nc1.get_metadata().first_block == b31.hash
        assert nc2.get_metadata().first_block == a33.hash
        assert nc3.get_metadata().first_block == a33.hash
        assert nc4.get_metadata().first_block == a32.hash

        assert self.manager.get_nc_storage(a33, nc1.hash).get('counter') == 2  # increments by nc4 and nc3
