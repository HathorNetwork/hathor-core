from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf import HathorSettings
from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.graphviz import GraphvizVisualizer
from hathor.nanocontracts import Blueprint, Context, NanoContract, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.util import not_none
from hathor.wallet import KeyPair, Wallet
from tests import unittest
from tests.utils import add_blocks_unlock_reward, get_genesis_key

settings = HathorSettings()


class MyTestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass


class NCHistoryIndexesTest(unittest.TestCase):
    __test__ = False

    def test_basic(self):
        blueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            blueprint_id: MyTestBlueprint
        })
        self.manager.tx_storage.nc_catalog = self.catalog

        parents = self.manager.get_new_tx_parents()
        nc = NanoContract(weight=1, inputs=[], outputs=[], parents=parents, storage=self.tx_storage)

        nc.nc_id = blueprint_id
        nc.nc_method = 'initialize'
        nc.nc_args_bytes = b''

        key = KeyPair.create(b'my-pass')
        privkey = key.get_private_key(b'my-pass')
        pubkey = privkey.public_key()
        data = nc.get_sighash_all_data()
        nc.nc_pubkey = get_public_key_bytes_compressed(pubkey)
        nc.nc_signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))

        self.manager.cpu_mining_service.resolve(nc)

        self.assertTrue(self.manager.on_new_tx(nc, fails_silently=False))

        contract_id = nc.hash
        nc_history_index = self.manager.tx_storage.indexes.nc_history
        self.assertEqual(
            [nc.hash],
            list(nc_history_index.get_sorted_from_contract_id(contract_id))
        )

        addresses_index = self.manager.tx_storage.indexes.addresses
        address = get_address_b58_from_public_key_bytes(nc.nc_pubkey)
        self.assertEqual(
            [nc.hash],
            list(addresses_index.get_sorted_from_address(address))
        )

    def test_latest_tx_timestamp(self) -> None:
        blueprint_id = b'x' * 32
        catalog = NCBlueprintCatalog({
            blueprint_id: MyTestBlueprint
        })
        manager = self.create_peer('testnet', nc_indices=True)
        nc_history_index = manager.tx_storage.indexes.nc_history
        manager.tx_storage.nc_catalog = catalog
        dag_builder = self.get_dag_builder(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = nop()

            nc2 <-- b11
        ''')
        artifacts.propagate_with(manager)

        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], NanoContract)
        assert nc_history_index.get_latest_tx_timestamp(nc1.hash) == nc2.timestamp
        assert nc_history_index.get_latest_tx_timestamp(nc2.hash) is None

    def test_transaction_count(self) -> None:
        path = self.mkdtemp()
        builder = self.get_builder().use_rocksdb(path).enable_nc_indices()
        manager = self.create_peer_from_builder(builder)
        indexes_manager = not_none(manager.tx_storage.indexes)
        nc_history_index = not_none(indexes_manager.nc_history)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        dag_builder = self.get_dag_builder(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = test_blueprint1.py, TestBlueprint1

            ocb2.ocb_private_key = "{private_key}"
            ocb2.ocb_password = "{password}"
            ocb2.ocb_code = test_blueprint1.py, TestBlueprint1

            nc1.nc_id = ocb1
            nc1.nc_method = initialize(0)

            nc2.nc_id = ocb2
            nc2.nc_method = initialize(0)

            nc3.nc_id = nc2
            nc3.nc_method = nop()

            nc4.nc_id = nc1
            nc4.nc_method = nop()

            nc5.nc_id = nc2
            nc5.nc_method = nop()

            nc6.nc_id = nc2
            nc6.nc_method = nop()

            nc7.nc_id = nc1
            nc7.nc_method = nop()

            ocb1 <-- ocb2 <-- b11
            b11 < nc1 < nc2 < nc3 < nc4 < nc5 < nc6 < nc7
        ''')

        artifacts.propagate_with(manager)
        nc1, nc2, nc6, nc7 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc6', 'nc7'], NanoContract)

        assert nc_history_index.get_transaction_count(nc1.hash) == 3
        assert nc_history_index.get_transaction_count(nc2.hash) == 4

        assert isinstance(manager.tx_storage, TransactionRocksDBStorage)
        manager.stop()
        manager.tx_storage._rocksdb_storage.close()

        # Test loading counts from existing db
        builder2 = self.get_builder().use_rocksdb(path).enable_nc_indices()
        manager2 = self.create_peer_from_builder(builder2)
        indexes_manager2 = not_none(manager2.tx_storage.indexes)
        nc_history_index = not_none(indexes_manager2.nc_history)

        assert nc_history_index.get_transaction_count(nc1.hash) == 3
        assert nc_history_index.get_transaction_count(nc2.hash) == 4


class RocksDBNCHistoryIndexesTest(NCHistoryIndexesTest):
    __test__ = True

    def setUp(self):
        import tempfile

        from hathor.transaction.storage import TransactionRocksDBStorage
        from hathor.transaction.vertex_parser import VertexParser

        super().setUp()
        self.wallet = Wallet()
        directory = tempfile.mkdtemp()
        self.tmpdirs.append(directory)
        rocksdb_storage = RocksDBStorage(path=directory)
        vertex_parser = VertexParser(settings=self._settings)
        self.tx_storage = TransactionRocksDBStorage(rocksdb_storage,
                                                    settings=self._settings,
                                                    vertex_parser=vertex_parser)
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True,
                                        utxo_index=True, nc_indices=True)
        self.blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = self.blocks[-1]

        self.graphviz = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True)
