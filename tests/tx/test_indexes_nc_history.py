import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf import HathorSettings
from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.graphviz import GraphvizVisualizer
from hathor.nanocontracts import Blueprint, Context, NanoContract, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.wallet import KeyPair, Wallet
from tests import unittest
from tests.utils import HAS_ROCKSDB, add_blocks_unlock_reward, get_genesis_key

settings = HathorSettings()


class MyTestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass


class BaseIndexesTest(unittest.TestCase):
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


class BaseMemoryIndexesTest(BaseIndexesTest):
    def setUp(self):
        from hathor.transaction.storage import TransactionMemoryStorage

        super().setUp()
        self.wallet = Wallet()
        self.tx_storage = TransactionMemoryStorage(settings=self._settings)
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True,
                                        utxo_index=True, nc_history_index=True)
        self.blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = self.blocks[-1]

        self.graphviz = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True)


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class BaseRocksDBIndexesTest(BaseIndexesTest):
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
                                        utxo_index=True, nc_history_index=True)
        self.blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = self.blocks[-1]

        self.graphviz = GraphvizVisualizer(self.tx_storage, include_verifications=True, include_funds=True)


class SyncV1MemoryIndexesTest(unittest.SyncV1Params, BaseMemoryIndexesTest):
    __test__ = True


class SyncV2MemoryIndexesTest(unittest.SyncV2Params, BaseMemoryIndexesTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeMemoryIndexesTest(unittest.SyncBridgeParams, SyncV2MemoryIndexesTest):
    pass


class SyncV1RocksDBIndexesTest(unittest.SyncV1Params, BaseRocksDBIndexesTest):
    __test__ = True


class SyncV2RocksDBIndexesTest(unittest.SyncV2Params, BaseRocksDBIndexesTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeRocksDBIndexesTest(unittest.SyncBridgeParams, SyncV2RocksDBIndexesTest):
    pass
