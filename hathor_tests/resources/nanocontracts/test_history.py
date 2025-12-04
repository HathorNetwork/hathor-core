from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.resources import NanoContractHistoryResource
from hathor.nanocontracts.utils import sign_openssl
from hathor.simulator.utils import add_new_block
from hathor.transaction import Transaction
from hathor.transaction.headers import NanoHeader
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward, get_genesis_key

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
    def setUp(self):
        super().setUp()

        self.manager = self.create_peer(
            'unittests',
            unlock_wallet=True,
            wallet_index=True,
            nc_indexes=True,
        )
        self.tx_storage = self.manager.tx_storage

        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        add_blocks_unlock_reward(self.manager)

        self.web = StubSite(NanoContractHistoryResource(self.manager))

        self.blueprint_id = b'1' * 32
        self.catalog = NCBlueprintCatalog({
            self.blueprint_id: MyBlueprint
        })
        self.tx_storage.nc_catalog = self.catalog
        self.nc_seqnum = 0

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
                 nc: Transaction,
                 nc_id: bytes,
                 nc_method: str,
                 nc_args: list[Any],
                 private_key: ec.EllipticCurvePrivateKeyWithSerialization) -> None:

        method = getattr(MyBlueprint, nc_method)
        method_parser = Method.from_callable(method)
        nc_args_bytes = method_parser.serialize_args_bytes(nc_args)

        nano_header = NanoHeader(
            tx=nc,
            nc_seqnum=self.nc_seqnum,
            nc_id=nc_id,
            nc_method=nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_address=b'',
            nc_script=b'',
            nc_actions=[],
        )
        nc.headers.append(nano_header)
        self.nc_seqnum += 1

        sign_openssl(nano_header, private_key)
        self.manager.cpu_mining_service.resolve(nc)

    def _create_contract(self, parents: list[bytes], timestamp: int) -> Transaction:
        nc = Transaction(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.tx_storage,
            timestamp=timestamp
        )
        self._fill_nc(nc, self.blueprint_id, 'initialize', [0], self.genesis_private_key)
        self.assertTrue(self.manager.on_new_tx(nc))
        add_new_block(self.manager)
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
        self.assertEqual(data1['has_more'], False)
        self.assertEqual(data1['history'][0]['hash'], nc1.hash.hex())
        self.assertEqual(data1['history'][0]['nc_method'], 'initialize')

        # Now we create a transaction
        tx1 = Transaction(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.tx_storage,
            timestamp=timestamp
        )
        self._fill_nc(tx1, nc1.hash, 'set_a', [1], self.genesis_private_key)
        self.assertTrue(self.manager.on_new_tx(tx1))
        add_new_block(self.manager)

        # Check both transactions belongs to nc1 history.
        response2 = yield self.web.get(
            'history',
            {
                b'id': nc1.hash.hex().encode('ascii'),
            }
        )
        data2 = response2.json_value()
        self.assertEqual(data2['has_more'], False)
        self.assertEqual(len(data2['history']), 2)
        ids = [tx['hash'] for tx in data2['history']]
        self.assertEqual(ids, [tx1.hash.hex(), nc1.hash.hex()])

        # Check paging works minimally with after
        response2a = yield self.web.get(
            'history',
            {
                b'id': nc1.hash.hex().encode('ascii'),
                b'count': b'1',
                b'after': ids[0].encode('ascii'),
            }
        )
        data2a = response2a.json_value()
        self.assertEqual(len(data2a['history']), 1)
        self.assertEqual(data2a['has_more'], False)
        self.assertEqual(data2a['count'], 1)
        self.assertEqual(data2a['after'], ids[0])
        self.assertEqual(data2a['before'], None)
        paginated_ids = [tx['hash'] for tx in data2a['history']]
        self.assertEqual(paginated_ids, [ids[1]])

        # Check paging works minimally with before
        response2b = yield self.web.get(
            'history',
            {
                b'id': nc1.hash.hex().encode('ascii'),
                b'count': b'1',
                b'before': ids[1].encode('ascii'),
            }
        )
        data2b = response2b.json_value()
        self.assertEqual(len(data2b['history']), 1)
        self.assertEqual(data2b['has_more'], False)
        self.assertEqual(data2b['count'], 1)
        self.assertEqual(data2b['after'], None)
        self.assertEqual(data2b['before'], ids[1])
        paginated_ids = [tx['hash'] for tx in data2b['history']]
        self.assertEqual(paginated_ids, [ids[0]])

        # Getting the first page only
        response2c = yield self.web.get(
            'history',
            {
                b'id': nc1.hash.hex().encode('ascii'),
                b'count': b'1',
            }
        )
        data2c = response2c.json_value()
        self.assertEqual(len(data2c['history']), 1)
        self.assertEqual(data2c['has_more'], True)
        self.assertEqual(data2c['count'], 1)
        self.assertEqual(data2c['after'], None)
        self.assertEqual(data2c['before'], None)
        paginated_ids = [tx['hash'] for tx in data2c['history']]
        self.assertEqual(paginated_ids, [ids[0]])

        # Make sure nc2 index still has only one tx.
        response3 = yield self.web.get(
            'history',
            {
                b'id': nc2.hash.hex().encode('ascii'),
            }
        )
        data3 = response3.json_value()
        self.assertEqual(data3['has_more'], False)
        self.assertEqual(len(data3['history']), 1)
        ids = set(tx['hash'] for tx in data3['history'])
        self.assertEqual(ids, {nc2.hash.hex()})
