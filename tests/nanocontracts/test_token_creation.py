
from hathor.conf import HathorSettings
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import NCAction, NCActionType, TokenUid, public
from hathor.transaction import Transaction
from tests import unittest
from tests.dag_builder.builder import TestDAGBuilder

settings = HathorSettings()


class MyBlueprint(Blueprint):
    a: str
    b: int

    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def withdraw(self, ctx: Context) -> None:
        pass


class NCNanoContractTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })

        self.manager = self.create_peer('testnet')
        self.manager.tx_storage.nc_catalog = self.catalog

    def test_token_creation(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        vertices = dag_builder.build_from_str(f'''
            blockchain genesis b[1..40]
            b30 < dummy

            tx1.nc_id = "{self.myblueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.out[0] = 10 HTR
            tx2.out[1] = 100 TKA  # call a method of an existing contract
            tx2.out[2] = 150 ABC  # ABC is a token created w/out using nano headers
            tx2.out[3] = 250 DEF  # create a new contract, no deposits
            tx2.out[4] = 350 GHI  # create a new contract, depositing 10 HTR into it
            tx2.out[5] = 450 JKL  # call a method of an existing contract with partial withdrawal

            tx3.out[1] = 200 TKB

            TKA.nc_id = tx1
            TKA.nc_method = withdraw()
            TKA.nc_withdrawal = 1 HTR

            DEF.nc_id = "{self.myblueprint_id.hex()}"
            DEF.nc_method = initialize()

            GHI.nc_id = "{self.myblueprint_id.hex()}"
            GHI.nc_method = initialize()
            GHI.nc_deposit = 10 HTR

            # JKL needs to deposit 5 HTR to create 450 JKL tokens.
            # - 3 HTR will be covered by a withdrawal from a contract
            # - 2 HTR will be covered by inputs
            JKL.nc_id = GHI
            JKL.nc_method = withdraw()
            JKL.nc_withdrawal = 3 HTR

            TKB.nc_id = tx1
            TKB.nc_method = withdraw()
            TKB.nc_withdrawal = 2 HTR

            TKA < TKB

            b31 --> tx1
            b32 --> tx2
            b33 --> tx3
        ''')

        vertices.propagate_with(self.manager, up_to='b31')
        tx1, = vertices.get_typed_vertices(['tx1'], Transaction)

        nc_storage = self.manager.get_best_block_nc_storage(tx1.hash)
        assert tx1.is_nano_contract()
        assert nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == 1

        vertices.propagate_with(self.manager, up_to='b32')
        TKA, ABC, DEF, GHI, JKL, tx2 = vertices.get_typed_vertices(
            ['TKA', 'ABC', 'DEF', 'GHI', 'JKL', 'tx2'],
            Transaction
        )

        assert not ABC.is_nano_contract()
        assert TKA.get_metadata().voided_by is None

        assert TKA.is_nano_contract()
        assert TKA.get_metadata().voided_by is None

        assert DEF.is_nano_contract()
        assert DEF.get_metadata().voided_by is None

        assert GHI.is_nano_contract()
        assert GHI.get_metadata().voided_by is None

        assert JKL.is_nano_contract()
        assert JKL.get_metadata().voided_by is None

        nc_storage = self.manager.get_best_block_nc_storage(tx1.hash)
        assert nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == 0

        ghi_nc_storage = self.manager.get_best_block_nc_storage(GHI.hash)
        assert ghi_nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == 7

        jkl_token_info = JKL._get_token_info_from_inputs()
        JKL._update_token_info_from_outputs(token_dict=jkl_token_info)
        assert jkl_token_info[settings.HATHOR_TOKEN_UID].amount == -2

        jkl_context = JKL.get_nano_header().get_context()
        htr_token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        assert jkl_context.actions[htr_token_uid] == NCAction(NCActionType.WITHDRAWAL, htr_token_uid, 3)

        assert not tx2.is_nano_contract()
        assert tx2.get_metadata().voided_by is None

        vertices.propagate_with(self.manager)
        TKB, tx3 = vertices.get_typed_vertices(['TKB', 'tx3'], Transaction)

        nc_storage = self.manager.get_best_block_nc_storage(tx1.hash)
        assert nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == 0

        assert TKB.is_nano_contract()
        assert TKB.get_metadata().voided_by == {TKB.hash, settings.NC_EXECUTION_FAIL_ID}

        assert not tx3.is_nano_contract()
        assert tx3.get_metadata().voided_by == {TKB.hash}
