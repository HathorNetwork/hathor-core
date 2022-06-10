import hashlib

from hathor.conf import HathorSettings
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import Blueprint, Context, NanoContract, public
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
from hathor.nanocontracts.types import NCAction, NCActionType
from hathor.simulator.trigger import StopAfterMinimumBalance, StopAfterNMinedBlocks
from hathor.transaction import TxOutput
from tests.simulation.base import SimulatorTestCase

settings = HathorSettings()


class MyBlueprint(Blueprint):
    total: int
    token_uid: bytes

    @public
    def initialize(self, ctx: Context, token_uid: bytes) -> None:
        self.total = 0
        self.token_uid = token_uid

    def _get_action(self, ctx: Context) -> NCAction:
        if len(ctx.actions) != 1:
            raise NCFail('only one action allowed')
        action = ctx.actions[self.token_uid]
        if action.token_uid != self.token_uid:
            raise NCFail('invalid token')
        return action

    @public
    def nop(self, ctx: Context, a: int) -> None:
        pass

    @public
    def deposit(self, ctx: Context) -> None:
        action = self._get_action(ctx)
        if action.type != NCActionType.DEPOSIT:
            raise NCFail('deposits only')
        self.total += action.amount

    @public
    def withdraw(self, ctx: Context) -> None:
        action = self._get_action(ctx)
        if action.type != NCActionType.WITHDRAWAL:
            raise NCFail('withdrawal only')
        self.total -= action.amount


class BaseSimulatorIndexesTestCase(SimulatorTestCase):
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

        self.token_uid = b'\0'
        trigger = StopAfterMinimumBalance(self.wallet, self.token_uid, 1)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

    def assertNoBlocksVoided(self):
        for blk in self.manager.tx_storage.get_all_transactions():
            if not blk.is_block:
                continue
            meta = blk.get_metadata()
            self.assertIsNone(meta.voided_by)

    def _gen_nc_tx(self, nc_id, nc_method, nc_args, nc=None):
        method_parser = NCMethodParser(getattr(MyBlueprint, nc_method))

        if nc is None:
            nc = NanoContract()
        nc.nc_id = nc_id
        nc.nc_method = nc_method
        nc.nc_args_bytes = method_parser.serialize_args(nc_args)

        address = self.wallet.get_unused_address()
        privkey = self.wallet.get_private_key(address)
        pubkey_bytes = privkey.sec()

        nc.nc_pubkey = pubkey_bytes
        data = nc.get_sighash_all()
        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        nc.nc_signature = privkey.sign(data_hash)

        nc.timestamp = int(self.manager.reactor.seconds())
        nc.parents = self.manager.get_new_tx_parents()
        nc.weight = self.manager.daa.minimum_tx_weight(nc)
        return nc

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
        tx.nc_method = 'unknown'
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
        tx.nc_method = 'deposit'
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
        self.assertNotEqual(getattr(tx, attr), value)
        setattr(tx, attr, value)
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
        self.assertEqual(meta.voided_by, {settings.NC_EXECUTION_FAIL_ID})

        self.assertNoBlocksVoided()

    def test_nc_consensus_success(self):
        nc = self._gen_nc_tx(self.myblueprint_id, 'initialize', [self.token_uid])
        self.manager.cpu_mining_service.resolve(nc)
        self.manager.on_new_tx(nc, fails_silently=False)
        self.assertIsNone(nc.get_metadata().voided_by)

        nc_id = nc.hash

        self.assertTrue(self.simulator.run(600))

        # Make a deposit.

        _inputs, deposit_amount = self.wallet.get_inputs_from_amount(1, self.manager.tx_storage)
        tx = self.wallet.prepare_transaction(NanoContract, _inputs, [])
        tx = self._gen_nc_tx(nc_id, 'deposit', [], nc=tx)
        self.manager.cpu_mining_service.resolve(tx)
        self.manager.on_new_tx(tx, fails_silently=False)
        self.assertIsNone(tx.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta = tx.get_metadata()
        self.assertIsNotNone(meta.first_block)
        self.assertIsNone(meta.voided_by)

        nc_storage = self.manager.consensus_algorithm.nc_storage_factory(nc_id)
        self.assertEqual(deposit_amount, nc_storage.get_balance(self.token_uid))

        # Make a withdrawal of 1 HTR.

        tx2 = NanoContract(outputs=[TxOutput(1, b'', 0)])
        tx2 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx2)
        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.on_new_tx(tx2, fails_silently=False)
        self.assertIsNone(tx2.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta2 = tx2.get_metadata()
        self.assertIsNotNone(meta2.first_block)
        self.assertIsNone(meta2.voided_by)

        nc_storage = self.manager.consensus_algorithm.nc_storage_factory(nc_id)
        self.assertEqual(deposit_amount - 1, nc_storage.get_balance(self.token_uid))

        # Make a withdrawal of the remainder.

        tx3 = NanoContract(outputs=[TxOutput(deposit_amount - 2, b'', 0)])
        tx3 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx3)
        self.manager.cpu_mining_service.resolve(tx3)
        self.manager.on_new_tx(tx3, fails_silently=False)
        self.assertIsNone(tx3.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta3 = tx3.get_metadata()
        self.assertIsNotNone(meta3.first_block)
        self.assertIsNone(meta3.voided_by)

        nc_storage = self.manager.consensus_algorithm.nc_storage_factory(nc_id)
        self.assertEqual(1, nc_storage.get_balance(self.token_uid))

        # Try to withdraw more than available, so it fails.

        tx4 = NanoContract(outputs=[TxOutput(2, b'', 0)])
        tx4 = self._gen_nc_tx(nc_id, 'withdraw', [], nc=tx4)
        self.manager.cpu_mining_service.resolve(tx4)
        self.manager.on_new_tx(tx4, fails_silently=False)
        self.assertIsNone(tx4.get_metadata().voided_by)

        trigger = StopAfterNMinedBlocks(self.miner, quantity=2)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

        meta4 = tx4.get_metadata()
        self.assertIsNotNone(meta4.first_block)
        self.assertEqual(meta4.voided_by, {settings.NC_EXECUTION_FAIL_ID})

        nc_storage = self.manager.consensus_algorithm.nc_storage_factory(nc_id)
        self.assertEqual(1, nc_storage.get_balance(self.token_uid))

        self.assertNoBlocksVoided()
