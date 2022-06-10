from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.crypto.util import get_public_key_bytes_compressed
from hathor.nanocontracts import Blueprint, Context, NanoContract, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.resources import NanoContractHistoryResource
from hathor.transaction.storage import TransactionMemoryStorage
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, get_genesis_key

settings = HathorSettings()


class MyBlueprint(Blueprint):
    a: int

    @public
    def initialize(self, ctx: Context, a: int) -> None:
        self.a = a

    @public
    def set_a(self, ctx: Context, a: int) -> None:
        self.a = a


class NanoContractHistoryTest(_BaseResourceTest._ResourceTest):
    _enable_sync_v1 = True
    _enable_sync_v2 = False

    def setUp(self):
        super().setUp()
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        self.manager = self.create_peer(
            'testnet',
            tx_storage=self.tx_storage,
            unlock_wallet=True,
            wallet_index=True,
            nc_history_index=True
        )
        add_blocks_unlock_reward(self.manager)

        self.web = StubSite(NanoContractHistoryResource(self.manager))

        self.blueprint_id = b'1' * 32
        self.catalog = NCBlueprintCatalog({
            self.blueprint_id: MyBlueprint
        })
        self.tx_storage.nc_catalog = self.catalog

    @inlineCallbacks
    def test_fail_missing_id(self):
        response1 = yield self.web.get('history')
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_invalid_id(self):
        response1 = yield self.web.get(
            'history',
            {
                b'id': b'xxx',
            }
        )
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_unknown_id(self):
        response1 = yield self.web.get(
            'history',
            {
                b'id': b'0' * 32,
            }
        )
        self.assertEqual(404, response1.responseCode)

    @inlineCallbacks
    def test_fail_not_contract_id(self):
        response1 = yield self.web.get(
            'history',
            {
                b'id': self.genesis_txs[0].hash.hex().encode('ascii'),
            }
        )
        self.assertEqual(404, response1.responseCode)

    def _fill_nc(self,
                 nc: NanoContract,
                 nc_id: bytes,
                 nc_method: str,
                 nc_args: list[Any],
                 private_key: ec.EllipticCurvePrivateKeyWithSerialization) -> None:

        nc.nc_id = nc_id
        nc.nc_method = nc_method

        method = getattr(MyBlueprint, nc_method)
        method_parser = NCMethodParser(method)
        nc.nc_args_bytes = method_parser.serialize_args(nc_args)

        pubkey = private_key.public_key()
        nc.nc_pubkey = get_public_key_bytes_compressed(pubkey)

        data = nc.get_sighash_all_data()
        nc.nc_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        self.manager.cpu_mining_service.resolve(nc)

    def _create_contract(self, parents: list[bytes], timestamp: int) -> NanoContract:
        nc = NanoContract(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.tx_storage,
            timestamp=timestamp
        )
        self._fill_nc(nc, self.blueprint_id, 'initialize', [0], self.genesis_private_key)
        self.manager.verification_service.verify(nc)
        self.assertTrue(self.manager.on_new_tx(nc, fails_silently=False))
        return nc

    @inlineCallbacks
    def test_success(self):
        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)
        nc1 = self._create_contract(parents, timestamp)

        timestamp += 1
        nc2 = self._create_contract(parents, timestamp)
        self.assertNotEqual(nc1.hash, nc2.hash)

        response1 = yield self.web.get(
            'history',
            {
                b'id': bytes(nc1.hash.hex(), 'utf-8'),
            }
        )
        data1 = response1.json_value()
        self.assertEqual(len(data1['history']), 1)
        self.assertEqual(data1['history'][0]['hash'], nc1.hash.hex())
        self.assertEqual(data1['history'][0]['nc_method'], 'initialize')

        # Now we create a transaction
        tx1 = NanoContract(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.tx_storage,
            timestamp=timestamp
        )
        self._fill_nc(tx1, nc1.hash, 'set_a', [1], self.genesis_private_key)
        self.manager.verification_service.verify(tx1)
        self.assertTrue(self.manager.on_new_tx(tx1, fails_silently=False))

        # Check both transactions belongs to nc1 history.
        response2 = yield self.web.get(
            'history',
            {
                b'id': nc1.hash.hex().encode('ascii'),
            }
        )
        data2 = response2.json_value()
        self.assertEqual(len(data2['history']), 2)
        ids = [tx['hash'] for tx in data2['history']]
        self.assertEqual(ids, [nc1.hash.hex(), tx1.hash.hex()])

        # Check paging works minimally.
        response2a = yield self.web.get(
            'history',
            {
                b'id': nc1.hash.hex().encode('ascii'),
                b'count': b'1',
                b'after': nc1.hash.hex().encode('ascii'),
            }
        )
        data2a = response2a.json_value()
        self.assertEqual(len(data2a['history']), 1)
        self.assertEqual(data2a['count'], 1)
        self.assertEqual(data2a['after'], nc1.hash.hex())
        ids = [tx['hash'] for tx in data2a['history']]
        self.assertEqual(ids, [tx1.hash.hex()])

        # Make sure nc2 index still has only one tx.
        response3 = yield self.web.get(
            'history',
            {
                b'id': nc2.hash.hex().encode('ascii'),
            }
        )
        data3 = response3.json_value()
        self.assertEqual(len(data3['history']), 1)
        ids = set(tx['hash'] for tx in data3['history'])
        self.assertEqual(ids, {nc2.hash.hex()})
