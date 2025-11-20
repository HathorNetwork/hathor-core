import hashlib
import math
from typing import Any, NamedTuple, Optional, TypeAlias

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_address_b58_from_bytes, get_public_key_bytes_compressed
from hathor.nanocontracts import Blueprint, Context, public, view
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.resources import NanoContractStateResource
from hathor.nanocontracts.types import (
    Address,
    CallerId,
    ContractId,
    NCActionType,
    NCDepositAction,
    Timestamp,
    TokenUid,
    VertexId,
)
from hathor.nanocontracts.utils import sign_openssl
from hathor.simulator.utils import add_new_block
from hathor.transaction import Transaction, TxInput
from hathor.transaction.headers import NanoHeader
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.scripts import P2PKH
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward, get_genesis_key

settings = HathorSettings()

Amount: TypeAlias = int


class MyNamedTuple(NamedTuple):
    amount1: int
    amount2: int
    address: Optional[Address]


class ReturnTuple(NamedTuple):
    foo: str
    token: TokenUid


class MyBlueprint(Blueprint):
    token_uid: TokenUid
    total: Amount
    date_last_bet: Timestamp
    address_details: dict[Address, dict[str, Amount]]
    bytes_field: bytes
    dict_with_bytes: dict[bytes, str]
    last_caller_id: CallerId
    last_bet_address: Address
    last_vertex_id: VertexId
    self_contract_id: ContractId

    @public
    def initialize(self, ctx: Context, token_uid: TokenUid, date_last_bet: Timestamp) -> None:
        self.token_uid = token_uid
        self.total = 0
        self.date_last_bet = date_last_bet
        self.address_details = {}
        self.bytes_field = b''
        self.dict_with_bytes = {}
        self.last_caller_id = ctx.caller_id
        self.last_bet_address = Address(b'\00' * 25)
        self.last_vertex_id = VertexId(ctx.vertex.hash)
        self.self_contract_id = ContractId(ctx.vertex.hash)

    @public(allow_deposit=True)
    def bet(self, ctx: Context, address: Address, score: str) -> None:
        action = ctx.get_single_action(self.token_uid)
        assert isinstance(action, NCDepositAction)
        self.total += action.amount
        partial = self.address_details.get(address, {})
        if score not in partial:
            partial[score] = action.amount
        else:
            partial[score] += action.amount
        self.address_details[address] = partial
        self.last_bet_address = address
        self.last_caller_id = ctx.caller_id
        self.last_vertex_id = VertexId(ctx.vertex.hash)

        encoded_score = score.encode()
        self.bytes_field = encoded_score
        self.dict_with_bytes[encoded_score] = score

    @view
    def has_result(self) -> bool:
        return False

    @view
    def add(self, a: int, b: int) -> int:
        return a + b

    @view
    def conditional_add(self, test_tuple: MyNamedTuple) -> Optional[int]:
        """A method only for testing that sums amount1 + amount2, in case
        the address is equal to WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN
        """
        conditional_address = 'WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN'
        if test_tuple.address and get_address_b58_from_bytes(test_tuple.address) == conditional_address:
            return test_tuple.amount1 + test_tuple.amount2

        return None

    @view
    def multiply(self, elements: list[int]) -> int:
        return math.prod(elements)

    @view
    def conditional_multiply_bytes(self, t: tuple[int, Optional[bytes]]) -> Optional[bytes]:
        multiplier = t[0]
        data = t[1]
        if not data:
            return None

        return multiplier * data

    @view
    def get_return_tuple(self) -> ReturnTuple:
        return ReturnTuple(
            foo='bar',
            token=TokenUid(b'\x11' * 32),
        )


class BaseNanoContractStateTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()

        self.manager = self.create_peer('unittests', unlock_wallet=True, wallet_index=True)
        self.tx_storage = self.manager.tx_storage

        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        *_, self.last_block = add_blocks_unlock_reward(self.manager)

        self.web = StubSite(NanoContractStateResource(self.manager))

        self.bet_id = bytes.fromhex('3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595')
        self.catalog = NCBlueprintCatalog({
            self.bet_id: MyBlueprint
        })

        self.tx_storage.nc_catalog = self.catalog
        self.nc_seqnum = 0

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

    def _fill_nc(
        self,
        nc: Transaction,
        nc_id: bytes,
        nc_method: str,
        nc_args: list[Any],
        private_key: ec.EllipticCurvePrivateKeyWithSerialization,
        *,
        nc_actions: list[NanoHeaderAction] | None = None
    ) -> None:

        method_parser = Method.from_callable(getattr(MyBlueprint, nc_method))
        nc_args_bytes = method_parser.serialize_args_bytes(nc_args)

        nano_header = NanoHeader(
            tx=nc,
            nc_seqnum=self.nc_seqnum,
            nc_id=nc_id,
            nc_method=nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_address=b'',
            nc_script=b'',
            nc_actions=nc_actions or [],
        )
        nc.headers.append(nano_header)
        self.nc_seqnum += 1

        sign_openssl(nano_header, private_key)
        self.manager.cpu_mining_service.resolve(nc)

    @inlineCallbacks
    def test_success(self):
        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        date_last_bet = 1699579721
        # Create bet nano contract
        nc = Transaction(
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
        self.assertTrue(self.manager.on_new_tx(nc))

        # Before the execution we can't get the state
        response0 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
            ]
        )
        self.assertEqual(404, response0.responseCode)
        # Execute the nano contract
        block1 = add_new_block(self.manager)

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
                (b'calls[]', b'conditional_add([2, 4, "WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN"])'),
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
        self.assertEqual(
            balances1,
            {settings.HATHOR_TOKEN_UID.hex(): {'value': '0', 'can_mint': False, 'can_melt': False}}
        )
        calls1 = data1['calls']
        self.assertEqual(calls1, {
            'has_result()': {'value': False},
            'unknown_method()': {'errmsg': "NCMethodNotFound('MyBlueprint.unknown_method')"},
            'add(5, 12)': {'value': 17},
            'conditional_add([2, 4, null])': {'value': None},
            'conditional_add([2, 4, "WewDeXWyvHP7jJTs7tjLoQfoB72LLxJQqN"])': {'value': 6},
            'multiply([2, 5, 8, 10])': {'value': 800},
            'conditional_multiply_bytes([5, "01"])': {'value': '0101010101'},
            'conditional_multiply_bytes([3, null])': {'value': None}
        })

        # Now we create a deposit in the nano contract with the genesis output
        inputs = [TxInput(self.genesis_blocks[0].hash, 0, b'')]
        address_b58 = self.genesis_blocks[0].outputs[0].to_human_readable()['address']
        nc_bet = Transaction(
            weight=1,
            inputs=inputs,
            outputs=[],
            parents=parents,
            storage=self.tx_storage,
            timestamp=timestamp
        )
        bet_result = '1x0'
        self._fill_nc(
            nc_bet,
            nc.hash,
            'bet',
            [decode_address(address_b58), bet_result],
            self.genesis_private_key,
            nc_actions=[
                NanoHeaderAction(
                    type=NCActionType.DEPOSIT,
                    token_index=0,
                    amount=self.genesis_blocks[0].outputs[0].value,
                )
            ]
        )

        data_to_sign = nc_bet.get_sighash_all()
        public_key_bytes = get_public_key_bytes_compressed(self.genesis_public_key)
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = self.genesis_private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        nc_bet.inputs[0].data = P2PKH.create_input_data(public_key_bytes, signature)

        self.manager.cpu_mining_service.resolve(nc_bet)
        # Add to DAG.
        self.assertTrue(self.manager.on_new_tx(nc_bet))
        # Execute the deposit
        block2 = add_new_block(self.manager)

        address_param = "address_details.a'{}'".format(address_b58)
        dict_with_bytes_param = "dict_with_bytes.b'{}'".format(bet_result.encode().hex())
        response2 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', b'last_caller_id'),
                (b'fields[]', b'last_bet_address'),
                (b'fields[]', b'last_vertex_id'),
                (b'fields[]', b'self_contract_id'),
                (b'fields[]', address_param.encode()),
                (b'fields[]', b'bytes_field'),
                (b'fields[]', dict_with_bytes_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
            ]
        )
        data2 = response2.json_value()
        fields2 = data2['fields']
        self.assertEqual(data2['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data2['blueprint_name'], 'MyBlueprint')
        self.assertEqual(len(data2['fields']), 10)
        self.assertEqual(fields2['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields2['total'], {'value': 10**11})
        self.assertEqual(fields2['date_last_bet'], {'value': date_last_bet})
        self.assertEqual(fields2['last_caller_id'], {'value': address_b58})
        self.assertEqual(fields2['last_bet_address'], {'value': address_b58})
        self.assertEqual(fields2['last_vertex_id'], {'value': nc_bet.hash.hex()})
        self.assertEqual(fields2['self_contract_id'], {'value': nc.hash.hex()})
        self.assertEqual(len(fields2[address_param]), 1)
        # TODO: RE-IMPLEMENT SUPPORT FOR THIS
        # FIXME
        self.assertEqual(fields2[address_param], {'errmsg': 'not a blueprint field'})
        # self.assertEqual(fields2[address_param], {'value': {'1x0': 10**11}})
        self.assertEqual(fields2['bytes_field'], {'value': bet_result.encode().hex()})
        # FIXME
        self.assertEqual(fields2[dict_with_bytes_param], {'errmsg': 'not a blueprint field'})
        # self.assertEqual(fields2[dict_with_bytes_param], {'value': '1x0'})
        balances2 = data2['balances']
        self.assertEqual(
            balances2,
            {settings.HATHOR_TOKEN_UID.hex(): {'value': '100000000000', 'can_mint': False, 'can_melt': False}}
        )

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
        self.assertEqual(
            balances3,
            {settings.HATHOR_TOKEN_UID.hex(): {'value': '100000000000', 'can_mint': False, 'can_melt': False}}
        )

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
                (b'block_hash', block1.hash.hex().encode('ascii')),
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
        self.assertEqual(
            balances4,
            {settings.HATHOR_TOKEN_UID.hex(): {'value': '0', 'can_mint': False, 'can_melt': False}}
        )

        # With block height
        response5 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', address_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
                (b'block_height', str(block1.static_metadata.height).encode('ascii')),
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
        self.assertEqual(
            balances5,
            {settings.HATHOR_TOKEN_UID.hex(): {'value': '0', 'can_mint': False, 'can_melt': False}}
        )

        # With block2.timestamp, should get block2 state
        response6 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', address_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
                (b'timestamp', str(block2.timestamp).encode('ascii')),
            ]
        )
        data6 = response6.json_value()
        fields6 = data6['fields']
        self.assertEqual(data6['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data6['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields6['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields6['total'], {'value': 10**11})
        self.assertEqual(fields6['date_last_bet'], {'value': date_last_bet})
        self.assertEqual(fields6[address_param].get('value'), None)
        balances6 = data6['balances']
        self.assertEqual(
            balances6,
            {settings.HATHOR_TOKEN_UID.hex(): {'value': '100000000000', 'can_mint': False, 'can_melt': False}}
        )

        # With block2.timestamp - 1, should get block1 state
        response7 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', address_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
                (b'timestamp', str(block2.timestamp - 1).encode('ascii')),
            ]
        )
        data7 = response7.json_value()
        fields7 = data7['fields']
        self.assertEqual(data7['blueprint_id'], self.bet_id.hex())
        self.assertEqual(data7['blueprint_name'], 'MyBlueprint')
        self.assertEqual(fields7['token_uid'], {'value': settings.HATHOR_TOKEN_UID.hex()})
        self.assertEqual(fields7['total'], {'value': 0})
        self.assertEqual(fields7['date_last_bet'], {'value': date_last_bet})
        self.assertEqual(fields7[address_param].get('value'), None)
        balances7 = data7['balances']
        self.assertEqual(
            balances7,
            {settings.HATHOR_TOKEN_UID.hex(): {'value': '0', 'can_mint': False, 'can_melt': False}}
        )

        # With block1.timestamp - 1, the contract doesn't exist
        response7 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'fields[]', b'total'),
                (b'fields[]', b'date_last_bet'),
                (b'fields[]', address_param.encode()),
                (b'balances[]', settings.HATHOR_TOKEN_UID.hex().encode('ascii')),
                (b'timestamp', str(block1.timestamp - 1).encode('ascii')),
            ]
        )
        self.assertEqual(response7.responseCode, 404)
        data7 = response7.json_value()
        self.assertEqual(data7['error'], f'Nano contract does not exist at block {self.last_block.hash_hex}.')

        # Validate errors using block_hash / block_height

        # Both parameters can't be used together
        response8 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_height', str(block1.static_metadata.height).encode('ascii')),
                (b'block_hash', block1.hash.hex().encode('ascii')),
            ]
        )
        self.assertEqual(400, response8.responseCode)

        # block_height does not exist
        response9 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_height', str(block1.static_metadata.height + 5).encode('ascii')),
            ]
        )
        self.assertEqual(400, response9.responseCode)

        # invalid block_hash does not exist
        response10 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_hash', '123'.encode('ascii')),
            ]
        )
        self.assertEqual(400, response10.responseCode)

        # block_hash is a tx
        response11 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'fields[]', b'token_uid'),
                (b'block_hash', nc_bet.hash.hex().encode('ascii')),
            ]
        )
        self.assertEqual(400, response11.responseCode)

        response12 = yield self.web.get(
            'state', [
                (b'id', nc.hash.hex().encode('ascii')),
                (b'calls[]', b'get_return_tuple()'),
            ]
        )
        assert response12.json_value()['calls']['get_return_tuple()'] == {
            'value': ['bar', '1' * 64]
        }
