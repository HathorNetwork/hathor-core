from typing import Optional

from twisted.internet.defer import inlineCallbacks

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.resources import BlueprintInfoResource
from hathor.nanocontracts.types import Address, Amount, SignedData, Timestamp, TokenUid, TxOutputScript
from tests.resources.base_resource import StubSite, _BaseResourceTest


class MyBlueprint(Blueprint):
    a_int: int
    a_str: str
    a_float: float
    a_bool: bool
    a_address: Address
    a_amount: Amount
    a_timestamp: Timestamp
    a_token_uid: TokenUid
    a_script: TxOutputScript
    a_signed_data: SignedData[str]
    a_dict: dict[str, int]
    a_tuple: tuple[str, int, bool]
    a_dict_dict_tuple: dict[str, tuple[str, int, float]]
    a_optional_int: Optional[int]

    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context, arg1: int, arg2: SignedData[str]) -> None:
        self.a = arg1

    def my_private_method_nop(self, arg1: int) -> int:
        return 1

    def my_private_method_2(self) -> dict[dict[str, int], tuple[bool, str, int, int]]:
        return {}

    def my_private_method_3(self) -> list[str]:
        return []

    def my_private_method_4(self) -> set[int]:
        return set()

    def my_private_method_5(self) -> str | None:
        return None

    def my_private_method_6(self) -> None | str:
        return None

    def my_private_method_7(self) -> str | int | bool | None:
        return 0


class BlueprintInfoTest(_BaseResourceTest._ResourceTest):
    _enable_sync_v1 = True
    _enable_sync_v2 = False

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')

        self.web = StubSite(BlueprintInfoResource(self.manager))

        self.blueprint_id = b'3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595'
        self.catalog = NCBlueprintCatalog({
            self.blueprint_id: MyBlueprint
        })
        self.manager.tx_storage.nc_catalog = self.catalog

    @inlineCallbacks
    def test_fail_missing_id(self):
        response1 = yield self.web.get('blueprint')
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_invalid_id(self):
        response1 = yield self.web.get(
            'blueprint',
            {
                b'blueprint_id': b'xxx',
            }
        )
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_unknown_id(self):
        response1 = yield self.web.get(
            'blueprint',
            {
                b'blueprint_id': b'0' * 32,
            }
        )
        self.assertEqual(404, response1.responseCode)

    @inlineCallbacks
    def test_success(self):
        response1 = yield self.web.get(
            'blueprint',
            {
                b'blueprint_id': bytes(self.blueprint_id.hex(), 'utf-8'),
            }
        )
        data = response1.json_value()

        self.assertEqual(data['id'], self.blueprint_id.hex())
        self.assertEqual(data['name'], 'MyBlueprint')
        self.assertEqual(data['attributes'], {
            'a_int': 'int',
            'a_str': 'str',
            'a_float': 'float',
            'a_bool': 'bool',
            'a_address': 'Address',
            'a_amount': 'Amount',
            'a_timestamp': 'Timestamp',
            'a_token_uid': 'TokenUid',
            'a_script': 'TxOutputScript',
            'a_signed_data': 'SignedData[str]',
            'a_dict': 'dict[str, int]',
            'a_tuple': 'tuple[str, int, bool]',
            'a_dict_dict_tuple': 'dict[str, tuple[str, int, float]]',
            'a_optional_int': 'int?',
        })
        self.assertEqual(data['public_methods'], {
            'initialize': {
                'args': [],
                'return_type': 'null',
            },
            'nop': {
                'args': [{
                    'name': 'arg1',
                    'type': 'int'
                }, {
                    'name': 'arg2',
                    'type': 'SignedData[str]',
                }],
                'return_type': 'null',
            },
        })
        expected_data = {
            'my_private_method_nop': {
                'args': [{
                    'name': 'arg1',
                    'type': 'int',
                }],
                'return_type': 'int',
            },
            'my_private_method_2': {
                'args': [],
                'return_type': 'dict[dict[str, int], tuple[bool, str, int, int]]',
            },
            'my_private_method_3': {
                'args': [],
                'return_type': 'list[str]',
            },
            'my_private_method_4': {
                'args': [],
                'return_type': 'set[int]',
            },
            'my_private_method_5': {
                'args': [],
                'return_type': 'str?',
            },
            'my_private_method_6': {
                'args': [],
                'return_type': 'str?',
            },
            'my_private_method_7': {
                'args': [],
                'return_type': 'union[str, int, bool, null]',
            },
        }
        self.assertEqual(data['private_methods'], expected_data)
