import pytest

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCInvalidFee, NCInvalidFeePaymentToken
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.types import ContractId, NCDepositAction, NCFee, NCWithdrawalAction, TokenUid, public
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Transaction
from tests.dag_builder.builder import TestDAGBuilder
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from tests.nanocontracts.test_reentrancy import HTR_TOKEN_UID


class MyBlueprint(Blueprint):
    @public(allow_deposit=True, allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_grant_authority=True, allow_withdrawal=True,)
    def create_fee_token(self, ctx: Context, name: str, symbol: str, amount: int) -> TokenUid:
        return self.syscall.create_fee_token(
            token_name=name,
            token_symbol=symbol,
            amount=amount,
            mint_authority=True,
            melt_authority=True,
        )

    @public(allow_deposit=True, allow_withdrawal=True, allow_grant_authority=True)
    def create_deposit_token(self, ctx: Context, name: str, symbol: str, amount: int) -> TokenUid:
        return self.syscall.create_deposit_token(token_name=name, token_symbol=symbol, amount=amount)

    @public(allow_deposit=True, allow_withdrawal=True)
    def noop(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_withdrawal=True)
    def get_tokens_from_nc(
        self,
        ctx: Context,
        nc_id: ContractId,
        token_uid: TokenUid,
        token_amount: int,
        fee_payment_token: TokenUid,
        fee_amount: int
    ) -> None:
        action = NCWithdrawalAction(token_uid=token_uid, amount=token_amount)
        fees = [NCFee(token_uid=TokenUid(fee_payment_token), amount=fee_amount)]
        self.syscall.get_contract(nc_id, blueprint_id=None).public(action, fees=fees).noop()

    @public(allow_deposit=True, allow_withdrawal=True)
    def move_tokens_to_nc(
        self,
        ctx: Context,
        nc_id: ContractId,
        token_uid: TokenUid,
        token_amount: int,
        fee_payment_token: TokenUid,
        fee_amount: int
    ) -> None:
        action = NCDepositAction(token_uid=token_uid, amount=token_amount)
        fees = [NCFee(token_uid=TokenUid(fee_payment_token), amount=fee_amount)]
        self.syscall.get_contract(nc_id, blueprint_id=None).public(action, fees=fees).noop()


class MyOtherBlueprint(Blueprint):
    fbt_uid: TokenUid

    @public(allow_deposit=True, allow_withdrawal=True, allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        self.fbt_uid = self.syscall.create_fee_token(
            token_name='FBT',
            token_symbol='FBT',
            amount=1_000_000,
            mint_authority=True,
            melt_authority=True,
        )

    @public(allow_deposit=True, allow_withdrawal=True)
    def move_tokens_to_nc(
        self,
        ctx: Context,
        nc_id: ContractId,
    ) -> None:
        action = NCDepositAction(token_uid=self.fbt_uid, amount=1000)
        fees = [NCFee(token_uid=TokenUid(HTR_TOKEN_UID), amount=1)]
        self.syscall.get_contract(nc_id, blueprint_id=None).public(action, fees=fees).noop()


class NCActionsFeeTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.my_blueprint_id = self.gen_random_blueprint_id()
        self.my_other_blueprint_id = self.gen_random_blueprint_id()
        self.nc_catalog.blueprints[self.my_blueprint_id] = MyBlueprint
        self.nc_catalog.blueprints[self.my_other_blueprint_id] = MyOtherBlueprint

        self.nc1_id = self.gen_random_contract_id()
        self.nc2_id = self.gen_random_contract_id()

        ctx = self.create_context()
        self.runner.create_contract(self.nc1_id, self.my_blueprint_id, ctx)
        self.runner.create_contract(self.nc2_id, self.my_blueprint_id, ctx)

        self.nc1_storage = self.runner.get_storage(self.nc1_id)
        self.nc2_storage = self.runner.get_storage(self.nc2_id)

    def test_actions_fee(self) -> None:
        # Starting state
        assert self.nc1_storage.get_all_balances() == {}
        assert self.nc2_storage.get_all_balances() == {}

        dbt_token_symbol = 'DBT'
        fbt_token_symbol = 'FBT'
        expected_dbt_token_uid = derive_child_token_id(ContractId(self.nc1_id), dbt_token_symbol)
        expected_fbt_token_uid = derive_child_token_id(ContractId(self.nc1_id), fbt_token_symbol)

        ctx_create_token = self.create_context([NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=100)])
        dbt_token_uid = self.runner.call_public_method(
            self.nc1_id,
            'create_deposit_token',
            ctx_create_token,
            name='DBT',
            symbol=dbt_token_symbol,
            amount=1000
        )
        fbt_token_uid = self.runner.call_public_method(
            self.nc1_id,
            'create_fee_token',
            self.create_context(),
            name='FBT',
            symbol=fbt_token_symbol,
            amount=10000
        )

        assert dbt_token_uid == expected_dbt_token_uid
        assert fbt_token_uid == expected_fbt_token_uid
        nc1_htr_balance_key = BalanceKey(nc_id=self.nc1_id, token_uid=HATHOR_TOKEN_UID)
        nc1_dbt_balance_key = BalanceKey(nc_id=self.nc1_id, token_uid=dbt_token_uid)
        nc1_fbt_balance_key = BalanceKey(nc_id=self.nc1_id, token_uid=fbt_token_uid)

        # deposit token creation charging 1% HTR (10)
        # fee token creation charging 1 HTR
        # 100 - 10 - 1 = 89
        assert self.nc1_storage.get_all_balances() == {
            nc1_htr_balance_key: Balance(value=89, can_mint=False, can_melt=False),
            nc1_dbt_balance_key: Balance(value=1000, can_mint=True, can_melt=True),
            nc1_fbt_balance_key: Balance(value=10000, can_mint=True, can_melt=True),
        }

        # move tokens from nc1 to nc2
        ctx_move_tokens_to_nc = self.create_context()
        self.runner.call_public_method(
            self.nc1_id,
            'move_tokens_to_nc',
            ctx_move_tokens_to_nc,
            self.nc2_id,
            token_uid=fbt_token_uid,
            token_amount=1000,
            fee_payment_token=TokenUid(HATHOR_TOKEN_UID),
            fee_amount=1
        )

        assert self.nc1_storage.get_all_balances() == {
            nc1_htr_balance_key: Balance(value=88, can_mint=False, can_melt=False),
            nc1_dbt_balance_key: Balance(value=1000, can_mint=True, can_melt=True),
            nc1_fbt_balance_key: Balance(value=9000, can_mint=True, can_melt=True),
        }

        nc2_fbt_balance_key = BalanceKey(nc_id=self.nc2_id, token_uid=fbt_token_uid)
        assert self.nc2_storage.get_all_balances() == {
            nc2_fbt_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
        }

        # move tokens from nc1 to nc2 paying with deposit tokens
        ctx_move_tokens_to_nc = self.create_context()
        self.runner.call_public_method(
            self.nc1_id,
            'move_tokens_to_nc',
            ctx_move_tokens_to_nc,
            self.nc2_id,
            token_uid=fbt_token_uid,
            token_amount=1000,
            fee_payment_token=dbt_token_uid,
            fee_amount=100
        )

        assert self.nc1_storage.get_all_balances() == {
            nc1_htr_balance_key: Balance(value=88, can_mint=False, can_melt=False),
            nc1_dbt_balance_key: Balance(value=900, can_mint=True, can_melt=True),
            nc1_fbt_balance_key: Balance(value=8000, can_mint=True, can_melt=True),
        }

        nc2_fbt_balance_key = BalanceKey(nc_id=self.nc2_id, token_uid=fbt_token_uid)
        assert self.nc2_storage.get_all_balances() == {
            nc2_fbt_balance_key: Balance(value=2000, can_mint=False, can_melt=False),
        }

        # get tokens from nc2 to nc1 paying with htr
        self.runner.call_public_method(
            self.nc1_id,
            'get_tokens_from_nc',
            self.create_context(),
            self.nc2_id,
            token_uid=fbt_token_uid,
            token_amount=1000,
            fee_payment_token=TokenUid(HATHOR_TOKEN_UID),
            fee_amount=1
        )

        assert self.nc1_storage.get_all_balances() == {
            nc1_htr_balance_key: Balance(value=87, can_mint=False, can_melt=False),
            nc1_dbt_balance_key: Balance(value=900, can_mint=True, can_melt=True),
            nc1_fbt_balance_key: Balance(value=9000, can_mint=True, can_melt=True),
        }

        nc2_fbt_balance_key = BalanceKey(nc_id=self.nc2_id, token_uid=fbt_token_uid)
        assert self.nc2_storage.get_all_balances() == {
            nc2_fbt_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
        }

        # get tokens from nc2 to nc1 paying with deposit token
        self.runner.call_public_method(
            self.nc1_id,
            'get_tokens_from_nc',
            self.create_context(),
            self.nc2_id,
            token_uid=fbt_token_uid,
            token_amount=1000,
            fee_payment_token=dbt_token_uid,
            fee_amount=100
        )

        assert self.nc1_storage.get_all_balances() == {
            nc1_htr_balance_key: Balance(value=87, can_mint=False, can_melt=False),
            nc1_dbt_balance_key: Balance(value=800, can_mint=True, can_melt=True),
            nc1_fbt_balance_key: Balance(value=10_000, can_mint=True, can_melt=True),
        }

        nc2_fbt_balance_key = BalanceKey(nc_id=self.nc2_id, token_uid=fbt_token_uid)
        assert self.nc2_storage.get_all_balances() == {
            nc2_fbt_balance_key: Balance(value=0, can_mint=False, can_melt=False),
        }

        # paying attempt with negative value is forbidden
        msg = 'fees should be a positive integer, got -100'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                token_uid=fbt_token_uid,
                token_amount=1000,
                fee_payment_token=dbt_token_uid,
                fee_amount=-100
            )
        # paying attempt with deposit token zero amount is forbidden
        msg = 'fees should be a positive integer, got 0'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                token_uid=fbt_token_uid,
                token_amount=1000,
                fee_payment_token=dbt_token_uid,
                fee_amount=0
            )

        # paying attempt with zero amount HTR is forbidden
        msg = 'fees should be a positive integer, got 0'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                token_uid=fbt_token_uid,
                token_amount=1000,
                fee_payment_token=TokenUid(HATHOR_TOKEN_UID),
                fee_amount=0
            )

        msg = 'fees using deposit custom tokens should be a multiple of 100, got 101'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                token_uid=fbt_token_uid,
                token_amount=1000,
                fee_payment_token=dbt_token_uid,
                fee_amount=101
            )

        # paying attempt with a valid value but incorrect amount
        msg = r'Fee payment balance is different than expected\. \(amount=2, expected=1\)'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                token_uid=fbt_token_uid,
                token_amount=1000,
                fee_payment_token=dbt_token_uid,
                fee_amount=200
            )

        # paying fees with a fee token is forbidden
        msg = "fee-based tokens aren't allowed for paying fees"
        with pytest.raises(NCInvalidFeePaymentToken, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                token_uid=fbt_token_uid,
                token_amount=1000,
                fee_payment_token=fbt_token_uid,
                fee_amount=100
            )

        assert self.nc1_storage.get_all_balances() == {
            nc1_htr_balance_key: Balance(value=87, can_mint=False, can_melt=False),
            nc1_dbt_balance_key: Balance(value=800, can_mint=True, can_melt=True),
            nc1_fbt_balance_key: Balance(value=10_000, can_mint=True, can_melt=True),
        }

        nc2_fbt_balance_key = BalanceKey(nc_id=self.nc2_id, token_uid=fbt_token_uid)
        assert self.nc2_storage.get_all_balances() == {
            nc2_fbt_balance_key: Balance(value=0, can_mint=False, can_melt=False),
        }

    def test_create_and_actions(self) -> None:
        # Check the contract creation with a token creation syscall and withdrawal of the created token
        self.nc3_id = self.gen_random_contract_id()
        fbt_token_uid = derive_child_token_id(self.nc3_id, 'FBT')

        htr_token_uid = TokenUid(HATHOR_TOKEN_UID)
        ctx = self.create_context(
            actions=[
                NCDepositAction(token_uid=htr_token_uid, amount=1),
                NCWithdrawalAction(token_uid=fbt_token_uid, amount=100_000)
            ],
        )
        self.runner.create_contract(self.nc3_id, self.my_other_blueprint_id, ctx)

        fbt_balance_key = BalanceKey(self.nc3_id, token_uid=fbt_token_uid)
        htr_balance_key = BalanceKey(self.nc3_id, token_uid=htr_token_uid)

        storage = self.runner.get_storage(self.nc3_id)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=900_000, can_mint=True, can_melt=True),
        }

    def test_token_index_updates(self) -> None:
        """Test token creation, token movement between contracts, and verify token indexes."""
        # Register the blueprint
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

        # Build the DAG: create two contracts, create tokens in first, then move tokens to second
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            tx1.nc_id = "{self.my_other_blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 100 HTR

            tx2.nc_id = "{self.my_blueprint_id.hex()}"
            tx2.nc_method = initialize()

            tx3.nc_id = tx1
            tx3.nc_method = move_tokens_to_nc(`tx2`)

            tx1 < b11 < tx2 < b12 < tx3 < b13
            tx1 <-- b11
            tx2 <-- b12
            tx3 <-- b13
        ''')

        # Propagate transactions and blocks
        artifacts.propagate_with(self.manager)

        tx1, tx2, tx3 = artifacts.get_typed_vertices(('tx1', 'tx2', 'tx3'), Transaction)

        # Get tokens index
        tokens_index = self.manager.tx_storage.indexes.tokens
        assert tokens_index is not None

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        fbt_token_info = tokens_index.get_token_info(fbt_id)
        assert fbt_token_info.get_total() == 1_000_000

        # Verify HTR total (genesis + mined blocks - fees paid)
        # Genesis: GENESIS_TOKENS + 13 blocks * INITIAL_TOKENS_PER_BLOCK
        # Fees: 1% of 1000 (10 HTR) + 1 HTR (fee token creation) + 1 HTR (move_tokens_to_nc)
        htr_token_info = tokens_index.get_token_info(HATHOR_TOKEN_UID)
        expected_htr_total = (
            self._settings.GENESIS_TOKENS
            + 13 * self._settings.INITIAL_TOKENS_PER_BLOCK
            - 1   # 1 HTR fee for fee token creation
            - 1   # 1 HTR fee for first move_tokens_to_nc
        )
        assert htr_token_info.get_total() == expected_htr_total

        # Verify contract balances after all operations
        nc1_storage = self.manager.get_best_block_nc_storage(tx1.hash)
        nc2_storage = self.manager.get_best_block_nc_storage(tx2.hash)

        assert nc1_storage.get_balance(HATHOR_TOKEN_UID) == Balance(value=98, can_mint=False, can_melt=False)
        assert nc1_storage.get_balance(fbt_id) == Balance(value=999_000, can_mint=True, can_melt=True)

        # nc2 should have: 0 HTR, 1000 FBT
        assert nc2_storage.get_balance(HATHOR_TOKEN_UID) == Balance(value=0, can_mint=False, can_melt=False)
        assert nc2_storage.get_balance(fbt_id) == Balance(value=1000, can_mint=False, can_melt=False)
