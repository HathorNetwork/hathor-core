import hashlib
import shutil
import tempfile
from typing import Any, Optional

import pytest

from hathor.conf import HathorSettings
from hathor.manager import HathorManager
from hathor.nanocontracts import Blueprint, Context, NanoContract, NCFail, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.simulator.trigger import StopAfterMinimumBalance, StopAfterNMinedBlocks
from hathor.transaction import BaseTransaction, TxOutput
from hathor.types import AddressB58
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from tests.simulation.base import SimulatorTestCase
from tests.utils import HAS_ROCKSDB

settings = HathorSettings()


class MyBlueprint(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        # Accepts all deposits and withdrawals.
        self.counter = 0

    @public
    def nop(self, ctx: Context) -> None:
        # Accepts all deposits and withdrawals.
        self.counter += 1

    @public
    def fail(self, ctx: Context) -> None:
        raise NCFail('fail')


class BaseIndexesTestCase(BlueprintTestCase, SimulatorTestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })

        self.manager.allow_mining_without_peers()
        self.manager.tx_storage.nc_catalog = self.catalog

        self.wallet = self.manager.wallet

        self.miner = self.simulator.create_miner(self.manager, hashpower=100e6)
        self.miner.start()

        self.token_uid = b'\0'
        trigger = StopAfterMinimumBalance(self.wallet, self.token_uid, 1)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))
        self.assertTrue(self.simulator.run(120))

    def fill_nc_tx(self,
                   nc: NanoContract,
                   nc_id: bytes,
                   nc_method: str,
                   nc_args: list[Any],
                   *,
                   address: Optional[AddressB58] = None) -> None:
        method_parser = NCMethodParser(getattr(MyBlueprint, nc_method))

        nc.nc_id = nc_id
        nc.nc_method = nc_method
        nc.nc_args_bytes = method_parser.serialize_args(nc_args)

        if address is None:
            address = self.wallet.get_unused_address()
        privkey = self.wallet.get_private_key(address)
        pubkey_bytes = privkey.sec()
        nc.nc_pubkey = pubkey_bytes

        data = nc.get_sighash_all()
        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        nc.nc_signature = privkey.sign(data_hash)

    def finish_and_broadcast_tx(self, tx: BaseTransaction, confirmations: int = 1) -> None:
        tx.timestamp = int(self.manager.reactor.seconds())
        tx.parents = self.manager.get_new_tx_parents()
        tx.weight = self.manager.daa.minimum_tx_weight(tx)

        # broadcast
        self.manager.cpu_mining_service.resolve(tx)
        self.manager.on_new_tx(tx, fails_silently=False)
        trigger = StopAfterNMinedBlocks(self.miner, quantity=confirmations)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))

    def test_tokens_index(self):
        token_info0 = self.manager.tx_storage.indexes.tokens.get_token_info(self.token_uid)
        new_blocks = 0

        # Deposits 1 HTR
        _inputs, deposit_amount = self.wallet.get_inputs_from_amount(1, self.manager.tx_storage)
        tx = self.wallet.prepare_transaction(NanoContract, _inputs, [])
        self.fill_nc_tx(tx, self.myblueprint_id, 'initialize', [])
        self.finish_and_broadcast_tx(tx, confirmations=2)
        new_blocks += 2

        self.assertIsNotNone(tx.get_metadata().first_block)
        self.assertIsNone(tx.get_metadata().voided_by)
        nc_id = tx.hash

        token_info1 = self.manager.tx_storage.indexes.tokens.get_token_info(self._settings.HATHOR_TOKEN_UID)
        self.assertEqual(token_info0.get_total() + 64_00 * new_blocks, token_info1.get_total())

        # Withdrawals 1 HTR
        tx2 = NanoContract(outputs=[TxOutput(1, b'', 0)])
        self.fill_nc_tx(tx2, nc_id, 'nop', [])
        self.finish_and_broadcast_tx(tx2, confirmations=2)
        new_blocks += 2

        token_info1 = self.manager.tx_storage.indexes.tokens.get_token_info(self._settings.HATHOR_TOKEN_UID)
        self.assertEqual(token_info0.get_total() + 64_00 * new_blocks, token_info1.get_total())

    def test_remove_voided_nano_tx_from_parents_1(self):
        vertices = self._run_test_remove_voided_nano_tx_from_parents('tx3 < b35')
        v = [node.name for node, _ in vertices.list]
        self.assertTrue(v.index('tx3') < v.index('b35'))

    def test_remove_voided_nano_tx_from_parents_2(self):
        vertices = self._run_test_remove_voided_nano_tx_from_parents('b35 < tx3')
        v = [node.name for node, _ in vertices.list]
        self.assertTrue(v.index('b35') < v.index('tx3'))

    def _run_test_remove_voided_nano_tx_from_parents(self, order: str):
        builder = self.get_dag_builder(self.manager)
        vertices = builder.build_from_str(f'''
            blockchain genesis b[0..40]
            b0.weight = 50

            b30 < dummy

            tx1.nc_id = "{self.myblueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 10 HTR
            tx1.out[0] <<< tx2

            tx2.nc_id = tx1
            tx2.nc_method = fail()
            tx2.out[0] <<< tx3

            tx3.nc_id = tx1
            tx3.nc_method = nop()

            tx1 <-- tx2 <-- b35

            {order}
        ''')

        for node, vertex in vertices.list:
            print()
            print(node.name)
            print()
            self.manager.on_new_tx(vertex, fails_silently=False)

        tx1 = vertices.by_name['tx1'].vertex
        tx2 = vertices.by_name['tx2'].vertex
        tx3 = vertices.by_name['tx3'].vertex
        b35 = vertices.by_name['b35'].vertex

        meta1 = tx1.get_metadata()
        meta2 = tx2.get_metadata()
        meta3 = tx3.get_metadata()

        # confirm that b35 belongs to the best blockchain
        self.assertIsNone(b35.get_metadata().voided_by)

        # only tx1 and tx2 should be confirmed
        self.assertEqual(meta1.first_block, b35.hash)
        self.assertEqual(meta2.first_block, b35.hash)
        self.assertIsNone(meta3.first_block)

        # tx1 succeeded; tx2 failed so tx3 must be voided
        self.assertIsNone(meta1.voided_by)
        self.assertEqual(meta2.voided_by, {tx2.hash, self._settings.NC_EXECUTION_FAIL_ID})
        self.assertEqual(meta3.voided_by, {tx2.hash})

        # check we are not using tx3 as parents for transactions
        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        self.assertNotIn(tx3.hash, parent_txs.can_include)
        self.assertNotIn(tx3.hash, parent_txs.must_include)

        # check we are not using tx3 as parents for blocks
        block_templates = self.manager.make_block_templates()
        for template in block_templates:
            self.assertNotIn(tx3.hash, template.parents)
            self.assertNotIn(tx3.hash, template.parents_any)

        return vertices


class MemoryIndexesTestCase(BaseIndexesTestCase):
    __test__ = True

    def build_manager(self) -> HathorManager:
        builder = self.simulator.get_default_builder()
        builder.enable_wallet_index()
        builder.use_memory()
        return self.simulator.create_peer(builder)


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class RocksDBIndexesTestCase(BaseIndexesTestCase):
    __test__ = True

    def build_manager(self) -> HathorManager:
        self.directory = tempfile.mkdtemp()

        builder = self.simulator.get_default_builder()
        builder.enable_wallet_index()
        builder.use_rocksdb(self.directory)
        return self.simulator.create_peer(builder)

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()
