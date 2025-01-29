from twisted.internet.defer import inlineCallbacks

from hathor.nanocontracts import Blueprint, OnChainBlueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.resources.blueprint import BlueprintInfoResource
from hathor.nanocontracts.types import BlueprintId
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor.simulator.utils import add_new_blocks
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseBlueprintInfoTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    # this is what subclasses have to define
    blueprint_id: BlueprintId

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.web = StubSite(BlueprintInfoResource(self.manager))

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
                'docstring': None,
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
                'docstring': 'No operation.',
            },
        })
        expected_data = {
            'my_private_method_nop': {
                'args': [{
                    'name': 'arg1',
                    'type': 'int',
                }],
                'return_type': 'int',
                'docstring': None,
            },
            'my_private_method_2': {
                'args': [],
                'return_type': 'dict[dict[str, int], tuple[bool, str, int, int]]',
                'docstring': None,
            },
            'my_private_method_3': {
                'args': [],
                'return_type': 'list[str]',
                'docstring': None,
            },
            'my_private_method_4': {
                'args': [],
                'return_type': 'set[int]',
                'docstring': None,
            },
            'my_private_method_5': {
                'args': [],
                'return_type': 'str?',
                'docstring': None,
            },
            'my_private_method_6': {
                'args': [],
                'return_type': 'str?',
                'docstring': None,
            },
            'my_private_method_7': {
                'args': [],
                'return_type': 'union[str, int, bool, null]',
                'docstring': None,
            },
        }
        self.assertEqual(data['private_methods'], expected_data)


class BuiltinBlueprintInfoTest(BaseBlueprintInfoTest):
    __test__ = True

    def setUp(self):
        super().setUp()
        from tests.resources.nanocontracts import my_blueprint
        self.blueprint_id = BlueprintId(b'3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595')
        self._create_builtin_blueprint(self.blueprint_id, my_blueprint.MyBlueprint)

    def _create_builtin_blueprint(self, blueprint_id: BlueprintId, blueprint_class: type[Blueprint]) -> None:
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            blueprint_id: blueprint_class,
        })


class OCBBlueprintInfoTest(BaseBlueprintInfoTest):
    __test__ = True

    def setUp(self):
        super().setUp()
        from tests.resources import nanocontracts
        nc_code = load_builtin_blueprint_for_ocb('my_blueprint.py', 'MyBlueprint', nanocontracts)
        blueprint = self._create_on_chain_blueprint(nc_code)
        self.manager.vertex_handler.on_new_vertex(blueprint, fails_silently=False)
        add_new_blocks(self.manager, 1, advance_clock=30)  # confirm the on-chain blueprint vertex
        self.blueprint_id = BlueprintId(blueprint.hash)

    def _create_on_chain_blueprint(self, nc_code: str) -> OnChainBlueprint:
        from hathor.nanocontracts.on_chain_blueprint import Code
        from tests.nanocontracts.on_chain_blueprints.utils import get_ocb_private_key
        code = Code.from_python_code(nc_code, self._settings)
        timestamp = self.manager.tx_storage.latest_timestamp + 1
        parents = self.manager.get_new_tx_parents(timestamp)
        blueprint = OnChainBlueprint(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.manager.tx_storage,
            timestamp=timestamp,
            code=code,
        )
        blueprint.weight = self.manager.daa.minimum_tx_weight(blueprint)
        blueprint.sign(get_ocb_private_key())
        self.manager.cpu_mining_service.resolve(blueprint)
        self.manager.reactor.advance(2)
        return blueprint
