from twisted.internet.defer import inlineCallbacks

from hathor.nanocontracts.resources import BlueprintSourceCodeResource
from hathor.nanocontracts.types import BlueprintId
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor.simulator.utils import add_new_blocks
from hathor_tests.resources.base_resource import StubSite
from hathor_tests.resources.nanocontracts.base_resource import GenericNanoResourceTest


class BaseBlueprintSourceCodeTest(GenericNanoResourceTest):
    __test__ = False

    # this is what subclasses have to define
    blueprint_id: BlueprintId
    blueprint_source: str

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.web = StubSite(BlueprintSourceCodeResource(self.manager))

    @inlineCallbacks
    def test_fail_missing_id(self):
        response1 = yield self.web.get('blueprint/source')
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_invalid_id(self):
        response1 = yield self.web.get(
            'blueprint/source',
            {
                b'blueprint_id': b'xxx',
            }
        )
        self.assertEqual(400, response1.responseCode)

    @inlineCallbacks
    def test_fail_unknown_id(self):
        response1 = yield self.web.get(
            'blueprint/source',
            {
                b'blueprint_id': b'0' * 32,
            }
        )
        self.assertEqual(404, response1.responseCode)

    @inlineCallbacks
    def test_success(self):
        response1 = yield self.web.get(
            'blueprint/source',
            {
                b'blueprint_id': bytes(self.blueprint_id.hex(), 'utf-8'),
            }
        )
        data = response1.json_value()
        self.assertEqual(self.blueprint_source, data['source_code'])


class BuiltinBlueprintSourceCodeTest(BaseBlueprintSourceCodeTest):
    __test__ = True

    blueprint_source = r'''from hathor import Blueprint, Context, export, public


@export
class TestBlueprint(Blueprint):
    """ This class is used by the test for the blueprint source code resource
        It must be in a separate file for the assert in the test
    """
    int_attribute: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.int_attribute = 0

    @public
    def sum(self, ctx: Context, arg1: int) -> None:
        self.int_attribute += arg1
'''

    def setUp(self):
        super().setUp()
        from hathor_tests.resources.nanocontracts import dummy_blueprint
        self.blueprint_id = BlueprintId(b'3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595')
        self.create_builtin_blueprint(self.manager, self.blueprint_id, dummy_blueprint.TestBlueprint)


class OCBBlueprintSourceCodeTest(BaseBlueprintSourceCodeTest):
    __test__ = True

    blueprint_source = r'''from hathor import Blueprint, Context, export, public


@export
class TestBlueprint(Blueprint):
    """ This class is used by the test for the blueprint source code resource
        It must be in a separate file for the assert in the test
    """
    int_attribute: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.int_attribute = 0

    @public
    def sum(self, ctx: Context, arg1: int) -> None:
        self.int_attribute += arg1
'''

    def setUp(self):
        super().setUp()
        from hathor_tests.resources import nanocontracts
        nc_code = load_builtin_blueprint_for_ocb('dummy_blueprint.py', 'TestBlueprint', nanocontracts)
        blueprint = self.create_on_chain_blueprint(self.manager, nc_code)
        self.manager.vertex_handler.on_new_relayed_vertex(blueprint)
        add_new_blocks(self.manager, 1, advance_clock=30)  # confirm the on-chain blueprint vertex
        self.blueprint_id = BlueprintId(blueprint.hash)
