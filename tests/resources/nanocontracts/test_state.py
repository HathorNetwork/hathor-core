import hashlib
import math
from typing import Any, NamedTuple, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_address_b58_from_bytes, get_public_key_bytes_compressed
from hathor.nanocontracts import Blueprint, Context, NanoContract, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.resources import NanoContractStateResource
from hathor.nanocontracts.types import Address, Amount, Timestamp, TokenUid
from hathor.simulator.utils import add_new_block
from hathor.transaction import TxInput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage import TransactionMemoryStorage
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, get_genesis_key

settings = HathorSettings()


class MyNamedTuple(NamedTuple):
    amount1: int
    amount2: int
    address: Optional[bytes]


class MyBlueprint(Blueprint):
    token_uid: TokenUid
    total: Amount
    date_last_bet: Timestamp
    address_details: dict[Address, dict[str, Amount]]

    @public
    def initialize(self, ctx: Context, token_uid: TokenUid, date_last_bet: Timestamp) -> None:
        self.token_uid = token_uid
        self.date_last_bet = date_last_bet
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

    def conditional_add(self, test_tuple: MyNamedTuple) -> Optional[int]:
        """A method only for testing that sums amount1 + amount2, in case
        the address is equal to WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN
        """
        conditional_address = 'WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN'
        if test_tuple.address and get_address_b58_from_bytes(test_tuple.address) == conditional_address:
            return test_tuple.amount1 + test_tuple.amount2

        return None

    def multiply(self, elements: list[int]) -> int:
        return math.prod(elements)

    def conditional_multiply_bytes(self, t: tuple[int, Optional[bytes]]) -> Optional[bytes]:
        multiplier = t[0]
        data = t[1]
        if not data:
            return None

        return multiplier * data


class BaseNanoContractStateTest(_BaseResourceTest._ResourceTest):
    _enable_sync_v1 = True
    _enable_sync_v2 = False

    def setUp(self):
        super().setUp()
        self.tx_storage = TransactionMemoryStorage(settings=self._settings)
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
        })
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_unknown_id(self):
        response1 = yield self.web.get('history', {
            b'id': b'0' * 32,
        })
        self.assertEqual(404, response1.responseCode)

    @inlineCallbacks
    def test_fail_not_contract_id(self):
        response1 = yield self.web.get('history', {
            b'id': self.genesis_txs[0].hash.hex().encode('ascii'),
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

        date_last_bet = 1699579721
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
            [settings.HATHOR_TOKEN_UID, date_last_bet],
            self.genesis_private_key,
        )
        self.assertTrue(self.manager.on_new_tx(nc, fails_silently=False))

        # Before the execution we can't get the state
        response0 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
             ]
        )
        # self.assertEqual(404, response0.responseCode)
        # Execute the nano contract
        block = add_new_block(self.manager)

        response1 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
                (b'calls[]', b'has_result()'),
                (b'calls[]', b'unknown_method()'),
                (b'calls[]', b'add(5, 12)'),
                (b'calls[]', b'conditional_add([2, 4, null])'),
                (b'calls[]', b'conditional_add([2, 4, "a\'WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN\'"])'),
                (b'calls[]', b'multiply([2, 5, 8, 10])'),
                (b'calls[]', b'conditional_multiply_bytes([5, "01"])'),
                (b'calls[]', b'conditional_multiply_bytes([3, null])'),
             ]
        )
        data1 = response1.json_value()
        fields1 = data1['fields']
        self.assertEqual(data1['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data1['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields1['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields1['total'], {'value': 0})
        self.assertEqual(fields1['date_last_bet'], {'value': date_last_bet})
        balances1 = data1['balances']
        self.assertEqual(balances1, {settings.HATHOR_TOKEN_UID.hex(): {'value': '0'}})
        calls1 = data1['calls']
        self.assertEqual(calls1, {
            'has_result()': {'value': False},
            'unknown_method()': {'errmsg': 'NCMethodNotFound()'},
            'add(5, 12)': {'value': 17},
            'conditional_add([2, 4, null])': {'value': None},
            'conditional_add([2, 4, "a\'WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN\'"])': {'value': 6},
            'multiply([2, 5, 8, 10])': {'value': 800},
            'conditional_multiply_bytes([5, "01"])': {'value': '0101010101'},
            'conditional_multiply_bytes([3, null])': {'value': None}
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
        # Add to DAG.
        self.assertTrue(self.manager.on_new_tx(nc_bet, fails_silently=False))
        # Execute the deposit
        add_new_block(self.manager)

        address_param = "address_details.a'{}'".format(address_b58)
        response2 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', address_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
            ]
        )
        data2 = response2.json_value()
        fields2 = data2['fields']
        self.assertEqual(data2['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data2['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields2['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields2['total'], {'value': 10**11})
        self.assertEqual(fields2['date_last_bet'], {'value': date_last_bet})
        self.assertEqual(len(fields2[address_param]), 1)
        self.assertEqual(fields2[address_param], {'value': {'1x0': 10**11}})
        balances2 = data2['balances']
        self.assertEqual(balances2, {settings.HATHOR_TOKEN_UID.hex(): {'value': '100000000000'}})

        # Test __all__ balance
        response3 = yield self.web.get(
            'state',
            {
                b'id': nc.hash.hex().encode('ascii'),
                b'balances[]': '__all__'.encode('ascii'),
            }
        )
        data3 = response3.json_value()
        self.assertEqual(data3['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data3['blueprint_name'], 'MyBlueprint')
        balances3 = data3['balances']
        self.assertEqual(balances3, {settings.HATHOR_TOKEN_UID.hex(): {'value': '100000000000'}})

        # Test getting the state in a previous block
        # With block hash
        response4 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', address_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
                (b'block_hash', block.hash.hex().encode('ascii')),
            ]
        )
        data4 = response4.json_value()
        fields4 = data4['fields']
        self.assertEqual(data4['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data4['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields4['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields4['total'], {'value': 0})
        self.assertEqual(fields4['date_last_bet'], {'value': date_last_bet})
        self.assertEqual(fields4[address_param].get('value'), None)
        balances4 = data4['balances']
        self.assertEqual(balances4, {settings.HATHOR_TOKEN_UID.hex(): {'value': '0'}})

        # With block height
        response5 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', address_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
                (b'block_height', str(block.static_metadata.height).encode('ascii')),
            ]
        )
        data5 = response5.json_value()
        fields5 = data5['fields']
        self.assertEqual(data5['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data5['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields5['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields5['total'], {'value': 0})
        self.assertEqual(fields5['date_last_bet'], {'value': date_last_bet})
        self.assertEqual(fields5[address_param].get('value'), None)
        balances5 = data5['balances']
        self.assertEqual(balances5, {settings.HATHOR_TOKEN_UID.hex(): {'value': '0'}})

        # Validate errors using block_hash / block_height

        # Both parameters can't be used together
        response6 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_height', str(block.static_metadata.height).encode('ascii')),
                (b'block_hash', block.hash.hex().encode('ascii')),
             ]
        )
        self.assertEqual(400, response6.responseCode)

        # block_height does not exist
        response7 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_height', str(block.static_metadata.height + 5).encode('ascii')),
             ]
        )
        self.assertEqual(400, response7.responseCode)

        # invalid block_hash does not exist
        response8 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_hash', '123'.encode('ascii')),
             ]
        )
        self.assertEqual(400, response8.responseCode)

        # block_hash is a tx
        response9 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_hash', nc_bet.hash.hex().encode('ascii')),
             ]
        )
        self.assertEqual(400, response9.responseCode)
