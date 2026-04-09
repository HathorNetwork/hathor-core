from hathor.conf import HathorSettings
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.nc_types import make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.types import ContractId, TokenUid, VertexId
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase

settings = HathorSettings()

INT_NC_TYPE = make_nc_type(int)


class MyBlueprint(Blueprint):
    x: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.x = 0

    @public
    def valid_assign(self, ctx: Context) -> None:
        self.x = 1

    @public
    def invalid_assign(self, ctx: Context) -> None:
        self.x = "2"  # type: ignore[assignment]


class NCGetContractTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        self.nc_id = ContractId(VertexId(b'1' * 32))
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.runner.create_contract(self.nc_id, self.blueprint_id, self.create_context())
        self.nc_storage = self.runner.get_storage(self.nc_id)

    def test_get_readwrite_contract(self) -> None:
        self.assertEqual(self.nc_storage.get_obj(b'x', INT_NC_TYPE), 0)

        self.runner.call_public_method(self.nc_id, 'valid_assign', self.create_context())
        self.assertEqual(self.nc_storage.get_obj(b'x', INT_NC_TYPE), 1)

        # XXX: the invalid_assign should fail as soon as put_obj is called, which makes this call fail with a NCFail,
        #      in the case where it doesn't fail immediately (and it's left to fail on commit), the exception raised
        #      will be a `TypeError` when commit is called.
        with self.assertRaises(NCFail):
            self.runner.call_public_method(self.nc_id, 'invalid_assign', self.create_context())
