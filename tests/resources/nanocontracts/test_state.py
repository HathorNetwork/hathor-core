import hashlib
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_public_key_bytes_compressed
from hathor.nanocontracts import Blueprint, Context, NanoContract, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.resources import NanoContractStateResource
from hathor.transaction import TxInput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.types import Address, Amount, Timestamp, TokenUid
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, get_genesis_key

settings = HathorSettings()


class MyBlueprint(Blueprint):
    token_uid: TokenUid
    total: Amount
    date_last_offer: Timestamp
    address_details: dict[Address, dict[str, Amount]]

    @public
    def initialize(self, ctx: Context, token_uid: TokenUid, date_last_offer: Timestamp) -> None:
        self.token_uid = token_uid
        self.date_last_offer = date_last_offer
        self.total = 0

    @public
    def bet(self, ctx: Context, address: Address, score: str) -> None:
        action = ctx.actions[self.token_uid]
        self.total += action.amount
        partial = self.address_details.get(address, {})
        if score not in partial:
            partial[score] = action.amount
        else:
            partial[score] += action.amount
        self.address_details[address] = partial

    def has_result(self) -> bool:
        return False

    def add(self, a: int, b: int) -> int:
        return a + b


class BaseNanoContractStateTest(_BaseResourceTest._ResourceTest):
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

        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True)
        add_blocks_unlock_reward(self.manager)

        self.web = StubSite(NanoContractStateResource(self.manager))

        self.bet_id = b'3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595'
        self.catalog = NCBlueprintCatalog({
            self.bet_id: MyBlueprint
        })

        self.tx_storage.nc_catalog = self.catalog

    @inlineCallbacks
    def test_fail_missing_id(self):
        response1 = yield self.web.get('state')
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_invalid_id(self):
        response1 = yield self.web.get('state', {
            b'id': b'xxx',
            b'fields[]': [],
        })
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_unknown_id(self):
        response1 = yield self.web.get('history', {
            b'id': b'0' * 32,
            b'fields[]': [],
        })
        self.assertEqual(404, response1.responseCode)

    @inlineCallbacks
    def test_fail_not_contract_id(self):
        response1 = yield self.web.get('history', {
            b'id': self.genesis_txs[0].hash.hex().encode('ascii'),
            b'fields[]': [],
        })
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

    @inlineCallbacks
    def test_success(self):
        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        date_last_offer = 1699579721
        # Create bet nano contract
        nc = NanoContract(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.tx_storage,
            timestamp=timestamp
        )
        self._fill_nc(
            nc,
            self.bet_id,
            'initialize',
            [settings.HATHOR_TOKEN_UID, date_last_offer],
            self.genesis_private_key,
        )
        self.manager.verification_service.verify(nc)
        self.assertTrue(self.manager.on_new_tx(nc, fails_silently=False))
        nc_storage = self.manager.consensus_algorithm.nc_storage_factory(nc.hash)
        # Execute the nano contract
        nc.execute(nc_storage)

        parser = NCMethodParser(MyBlueprint.add)
        add_args_hex = parser.serialize_args([5, 12]).hex()
        add_call = f'add({add_args_hex})'

        response1 = yield self.web.get(
            'state',
            {
                b'id': nc.hash.hex().encode('ascii'),
                b'fields[]': [b'token_uid', b'total', b'date_last_offer'],
                b'balances[]': [settings.HATHOR_TOKEN_UID.hex().encode('ascii')],
                b'calls[]': [
                    b'has_result()',
                    b'unknown_method()',
                    add_call.encode('ascii'),
                ],
            }
        )
        data1 = response1.json_value()
        fields1 = data1['fields']
        self.assertEqual(data1['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields1['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields1['total'], {'value': 0})
        self.assertEqual(fields1['date_last_offer'], {'value': date_last_offer})
        balances1 = data1['balances']
        self.assertEqual(balances1, {settings.HATHOR_TOKEN_UID.hex(): {'value': '0'}})
        calls1 = data1['calls']
        self.assertEqual(calls1, {
            'has_result()': {'value': False},
            'unknown_method()': {'errmsg': 'NCMethodNotFound()'},
            add_call: {'value': 17},
        })

        # Now we create a deposit in the nano contract with the genesis output
        inputs = [TxInput(self.genesis_blocks[0].hash, 0, b'')]
        address_b58 = self.genesis_blocks[0].outputs[0].to_human_readable()['address']
        nc_bet = NanoContract(
            weight=1,
            inputs=inputs,
            outputs=[],
            parents=parents,
            storage=self.tx_storage,
            timestamp=timestamp
        )
        self._fill_nc(
            nc_bet,
            nc.hash,
            'bet',
            [decode_address(address_b58), '1x0'],
            self.genesis_private_key,
        )

        data_to_sign = nc_bet.get_sighash_all()
        public_key_bytes = get_public_key_bytes_compressed(self.genesis_public_key)
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = self.genesis_private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        nc_bet.inputs[0].data = P2PKH.create_input_data(public_key_bytes, signature)

        self.manager.cpu_mining_service.resolve(nc_bet)
        self.manager.verification_service.verify(nc_bet)
        # Add to DAG.
        self.assertTrue(self.manager.on_new_tx(nc_bet, fails_silently=False))
        # Execute the deposit
        nc_bet.execute(nc_storage)

        address_param = "address_details.a'{}'".format(address_b58)
        response2 = yield self.web.get(
            'state',
            {
                b'id': nc.hash.hex().encode('ascii'),
                b'fields[]': [b'token_uid', b'total', b'date_last_offer', address_param.encode()],
                b'balances[]': [settings.HATHOR_TOKEN_UID.hex().encode('ascii')],
            }
        )
        data2 = response2.json_value()
        fields2 = data2['fields']
        self.assertEqual(data2['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields2['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields2['total'], {'value': 10**11})
        self.assertEqual(fields2['date_last_offer'], {'value': date_last_offer})
        self.assertEqual(len(fields2[address_param]), 1)
        self.assertEqual(fields2[address_param], {'value': {'1x0': 10**11}})
        balances2 = data2['balances']
        self.assertEqual(balances2, {settings.HATHOR_TOKEN_UID.hex(): {'value': '100000000000'}})
