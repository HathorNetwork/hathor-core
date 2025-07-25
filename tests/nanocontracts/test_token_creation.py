
from hathor.conf import HathorSettings
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.types import ContractId, NCWithdrawalAction, TokenUid, VertexId, public
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.token_creation_tx import TokenDescription
from tests import unittest
from tests.dag_builder.builder import TestDAGBuilder
from tests.nanocontracts.utils import assert_nc_failure_reason

settings = HathorSettings()


class MyBlueprint(Blueprint):
    a: str
    b: int

    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_withdrawal=True)
    def withdraw(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True)
    def create_token(
        self,
        ctx: Context,
        token_name: str,
        token_symbol: str,
        amount: int,
        mint_authority: bool,
        melt_authority: bool,
    ) -> None:
        self.syscall.create_token(token_name, token_symbol, amount, mint_authority, melt_authority)


class NCNanoContractTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })

        self.manager = self.create_peer('unittests', nc_log_config=NCLogConfig.FAILED, wallet_index=True)
        self.manager.tx_storage.nc_catalog = self.catalog

    def test_token_creation_by_vertex(self) -> None:
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
        assert nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == Balance(value=1, can_mint=False, can_melt=False)

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
        assert nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == Balance(value=0, can_mint=False, can_melt=False)

        ghi_nc_storage = self.manager.get_best_block_nc_storage(GHI.hash)
        assert ghi_nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == (
            Balance(value=7, can_mint=False, can_melt=False)
        )

        jkl_token_info = JKL._get_token_info_from_inputs()
        JKL._update_token_info_from_outputs(token_dict=jkl_token_info)
        assert jkl_token_info[settings.HATHOR_TOKEN_UID].amount == -2

        jkl_context = JKL.get_nano_header().get_context()
        htr_token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        assert jkl_context.actions[htr_token_uid] == (NCWithdrawalAction(token_uid=htr_token_uid, amount=3),)

        assert not tx2.is_nano_contract()
        assert tx2.get_metadata().voided_by is None

        vertices.propagate_with(self.manager)
        TKB, tx3 = vertices.get_typed_vertices(['TKB', 'tx3'], Transaction)

        nc_storage = self.manager.get_best_block_nc_storage(tx1.hash)
        assert nc_storage.get_balance(settings.HATHOR_TOKEN_UID) == Balance(value=0, can_mint=False, can_melt=False)

        assert TKB.is_nano_contract()
        assert TKB.get_metadata().voided_by == {TKB.hash, NC_EXECUTION_FAIL_ID}

        assert not tx3.is_nano_contract()
        assert tx3.get_metadata().voided_by == {TKB.hash}

    def test_token_creation_by_contract(self) -> None:
        token_symbol = 'TKA'

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        vertices = dag_builder.build_from_str(f'''
            blockchain genesis b[1..40]
            b30 < dummy

            tx1.nc_id = "{self.myblueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx2.nc_id = tx1
            tx2.nc_method = create_token("MyToken", "{token_symbol}", 100, false, false)
            tx2.nc_deposit = 3 HTR

            tx3.nc_id = tx1
            tx3.nc_method = create_token("MyToken (2)", "{token_symbol}", 50, true, false)
            tx3.nc_deposit = 1 HTR

            tx2 < tx3

            b31 --> tx1
            b31 --> tx2
            b32 --> tx3
        ''')

        vertices.propagate_with(self.manager)

        tx1, tx2, tx3 = vertices.get_typed_vertices(['tx1', 'tx2', 'tx3'], Transaction)
        b31, b32 = vertices.get_typed_vertices(['b31', 'b32'], Block)

        # Uncomment for debugging:
        # from tests.nanocontracts.utils import get_nc_failure_entry
        # failure_entry = get_nc_failure_entry(manager=self.manager, tx_id=tx2.hash, block_id=b31.hash)
        # print(failure_entry.error_traceback)

        assert tx1.get_metadata().voided_by is None
        assert tx1.get_metadata().nc_execution is NCExecutionState.SUCCESS

        assert tx2.get_metadata().voided_by is None
        assert tx2.get_metadata().nc_execution is NCExecutionState.SUCCESS

        assert tx3.get_metadata().voided_by == {tx3.hash, NC_EXECUTION_FAIL_ID}
        assert tx3.get_metadata().nc_execution is NCExecutionState.FAILURE

        assert b31.get_metadata().voided_by is None
        assert b32.get_metadata().voided_by is None

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx3.hash,
            block_id=b32.hash,
            reason='NCTokenAlreadyExists',
        )

        child_token_id = derive_child_token_id(ContractId(VertexId(tx1.hash)), token_symbol)
        child_token_balance_key = BalanceKey(nc_id=tx1.hash, token_uid=child_token_id)
        htr_balance_key = BalanceKey(nc_id=tx1.hash, token_uid=settings.HATHOR_TOKEN_UID)

        block_storage = self.manager.get_nc_block_storage(b31)
        expected_token_info = TokenDescription(
            token_id=child_token_id,
            token_name='MyToken',
            token_symbol=token_symbol,
        )
        assert block_storage.get_token_description(child_token_id) == expected_token_info

        nc_storage = block_storage.get_contract_storage(tx1.hash)
        assert nc_storage.get_all_balances() == {
            child_token_balance_key: Balance(value=100, can_mint=False, can_melt=False),
            htr_balance_key: Balance(value=2, can_mint=False, can_melt=False),
        }

        tokens_index = self.manager.tx_storage.indexes.tokens
        assert tokens_index.get_token_info(settings.HATHOR_TOKEN_UID).get_total() == (
            settings.GENESIS_TOKENS + 40 * settings.INITIAL_TOKENS_PER_BLOCK - 1
        )
        assert tokens_index.get_token_info(child_token_id).get_total() == 100
