from twisted.internet.defer import inlineCallbacks

from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.resources import BlueprintSourceCodeResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.resources.nanocontracts.dummy_blueprint import TestBlueprint


class BlueprintSourceCodeTest(_BaseResourceTest._ResourceTest):
    _enable_sync_v1 = True
    _enable_sync_v2 = False

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')

        self.web = StubSite(BlueprintSourceCodeResource(self.manager))

        self.blueprint_id = b'3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595'
        self.catalog = NCBlueprintCatalog({
            self.blueprint_id: TestBlueprint
        })
        self.manager.tx_storage.nc_catalog = self.catalog

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
        blueprint_str = ('from hathor.nanocontracts import Blueprint, Context, public\n\n\nclass '
                         'TestBlueprint(Blueprint):\n    """ This class is used by the test for t'
                         'he blueprint source code resource\n        It must be in a separate fil'
                         'e for the assert in the test\n    """\n    int_attribute: int\n\n    @p'
                         'ublic\n    def initialize(self, ctx: Context) -> None:\n        self.in'
                         't_attribute = 0\n\n    @public\n    def sum(self, ctx: Context, arg1: i'
                         'nt) -> None:\n        self.int_attribute += arg1\n')
        self.assertEqual(blueprint_str, data['source_code'])
