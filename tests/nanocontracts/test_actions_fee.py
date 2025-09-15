import pytest

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCInvalidFee, NCInvalidPaymentToken
from hathor.nanocontracts.nc_types import NCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCDepositAction,
    NCFee,
    NCWithdrawalAction,
    TokenUid,
    public,
)
from hathor.nanocontracts.utils import derive_child_token_id
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase

CONTRACT_NC_TYPE = make_nc_type(ContractId)
BLUEPRINT_NC_TYPE = make_nc_type(BlueprintId)
OPT_CONTRACT_NC_TYPE: NCType[ContractId | None] = make_nc_type(ContractId | None)  # type: ignore[arg-type]
OPT_BLUEPRINT_NC_TYPE: NCType[BlueprintId | None] = make_nc_type(BlueprintId | None)  # type: ignore[arg-type]


class MyBlueprint(Blueprint):
    @public(allow_deposit=True, allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_grant_authority=True, allow_withdrawal=True,)
    def create_fee_token(self, ctx: Context, name: str, symbol: str, amount: int) -> TokenUid:
        return self.syscall.create_fee_token(name, symbol, amount, True, True)

    @public(allow_deposit=True, allow_withdrawal=True, allow_grant_authority=True)
    def create_deposit_token(self, ctx: Context, name: str, symbol: str, amount: int) -> TokenUid:
        return self.syscall.create_deposit_token(name, symbol, amount)

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
        actions = [NCWithdrawalAction(token_uid=token_uid, amount=token_amount)]
        fees = [NCFee(token_uid=TokenUid(fee_payment_token), amount=fee_amount)]
        self.syscall.call_public_method(nc_id, 'noop', actions, fees)

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
        actions = [NCDepositAction(token_uid=token_uid, amount=token_amount)]
        fees = [NCFee(token_uid=TokenUid(fee_payment_token), amount=fee_amount)]
        self.syscall.call_public_method(nc_id, 'noop', actions, fees)


class MyOtherBlueprint(Blueprint):

    @public(allow_deposit=True, allow_withdrawal=True, allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        self.syscall.create_fee_token('FBT', 'FBT', 1_000_000, True, True)


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
            'DBT',
            dbt_token_symbol,
            1000)
        fbt_token_uid = self.runner.call_public_method(
            self.nc1_id,
            'create_fee_token',
            self.create_context(),
            'FBT',
            fbt_token_symbol,
            10000
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
            fbt_token_uid,  # token to move
            1000,  # amount to move
            TokenUid(HATHOR_TOKEN_UID),  # payment_token
            1  # fee_amount
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
            fbt_token_uid,  # token to move
            1000,  # amount to move
            dbt_token_uid,  # payment_token
            100  # fee_amount
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
            fbt_token_uid,  # token to move
            1000,  # amount to move
            TokenUid(HATHOR_TOKEN_UID),  # payment_token
            1  # fee_amount
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
            fbt_token_uid,  # token to move
            1000,  # amount to move
            dbt_token_uid,  # payment_token
            100  # fee_amount
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
        msg = 'amount must be positive'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                fbt_token_uid,  # token to move
                1000,  # amount to move
                dbt_token_uid,  # payment_token
                -100  # fee_amount
            )

        # paying attempt with negative value is forbidden
        msg = 'fee amount must be an integer and multiple of 100 when using deposit tokens'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                fbt_token_uid,  # token to move
                1000,  # amount to move
                dbt_token_uid,  # payment_token
                101  # fee_amount
            )

        # paying attempt with a valid value but incorrect amount
        msg = r'Fee payment balance is different than expected\. \(amount=2, expected=1\)'
        with pytest.raises(NCInvalidFee, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                fbt_token_uid,  # token to move
                1000,  # amount to move
                dbt_token_uid,  # payment_token
                200  # fee_amount
            )

        # paying fees with a fee token is forbidden
        msg = "fee-based tokens aren't allowed for paying fees"
        with pytest.raises(NCInvalidPaymentToken, match=msg):
            self.runner.call_public_method(
                self.nc1_id,
                'move_tokens_to_nc',
                self.create_context(),
                self.nc2_id,
                fbt_token_uid,  # token to move
                1000,  # amount to move
                fbt_token_uid,  # payment_token
                100  # fee_amount
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

    def test_create_and_actions(self):
        # Check the contract creation with a token creation syscall and withdrawal of the created token
        self.nc3_id = self.gen_random_contract_id()
        fbt_token_uid = derive_child_token_id(self.nc3_id, 'FBT')

        htr_token_uid = TokenUid(HATHOR_TOKEN_UID)
        ctx = self.create_context(
            actions=[
                NCDepositAction(token_uid=htr_token_uid, amount=1),
                NCWithdrawalAction(token_uid=fbt_token_uid, amount=100_000)
            ],
            fees=[NCFee(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=1)]
        )
        self.runner.create_contract(self.nc3_id, self.my_other_blueprint_id, ctx)

        fbt_balance_key = BalanceKey(self.nc3_id, token_uid=fbt_token_uid)
        htr_balance_key = BalanceKey(self.nc3_id, token_uid=htr_token_uid)

        storage = self.runner.get_storage(self.nc3_id)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=900_000, can_mint=True, can_melt=True),
        }
