from collections.abc import Generator
from typing import Any

from twisted.internet.defer import Deferred, inlineCallbacks

from hathor.nanocontracts.resources.blueprint import BlueprintInfoResource
from hathor.nanocontracts.types import BlueprintId, VertexId
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor.simulator.utils import add_new_blocks
from hathor_tests.resources.base_resource import StubSite
from hathor_tests.resources.nanocontracts.base_resource import GenericNanoResourceTest


class BaseBlueprintInfoTest(GenericNanoResourceTest):
    # this is what subclasses have to define
    blueprint_id: BlueprintId

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.web = StubSite(BlueprintInfoResource(self.manager))

    @inlineCallbacks
    def test_fail_missing_id(self) -> Generator[Deferred[Any], Any, None]:
        response1 = yield self.web.get('blueprint')
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_invalid_id(self) -> Generator[Deferred[Any], Any, None]:
        response1 = yield self.web.get(
            'blueprint',
            {
                b'blueprint_id': b'xxx',
            }
        )
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_unknown_id(self) -> Generator[Deferred[Any], Any, None]:
        response1 = yield self.web.get(
            'blueprint',
            {
                b'blueprint_id': b'0' * 32,
            }
        )
        self.assertEqual(404, response1.responseCode)

    @inlineCallbacks
    def test_success(self) -> Generator[Deferred[Any], Any, None]:
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
            'a_bool': 'bool',
            'a_address': 'Address',
            'a_amount': 'Amount',
            'a_timestamp': 'Timestamp',
            'a_token_uid': 'TokenUid',
            'a_script': 'TxOutputScript',
            'a_signed_data': 'SignedData[str]',
            'a_dict': 'dict[str, int]',
            'a_tuple': 'tuple[str, int, bool]',
            'a_dict_dict_tuple': 'dict[str, tuple[str, int]]',
            'a_optional_int': 'int?',
            'a_caller_id': 'CallerId',
        })
        self.assertEqual(data['public_methods'], {
            'initialize': {
                'args': [{
                    'name': 'arg1',
                    'type': 'int',
                }],
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
        from hathor_tests.resources.nanocontracts import my_blueprint
        self.blueprint_id = BlueprintId(VertexId(b'3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595'))
        self.create_builtin_blueprint(self.manager, self.blueprint_id, my_blueprint.MyBlueprint)


class OCBBlueprintInfoTest(BaseBlueprintInfoTest):
    __test__ = True

    def setUp(self):
        super().setUp()
        from hathor_tests.resources import nanocontracts
        nc_code = load_builtin_blueprint_for_ocb('my_blueprint.py', 'MyBlueprint', nanocontracts)
        blueprint = self.create_on_chain_blueprint(self.manager, nc_code)
        self.manager.vertex_handler.on_new_relayed_vertex(blueprint)
        add_new_blocks(self.manager, 1, advance_clock=30)  # confirm the on-chain blueprint vertex
        self.blueprint_id = BlueprintId(VertexId(blueprint.hash))
