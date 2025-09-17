from typing import Optional

import pytest

from hathor.nanocontracts import HATHOR_TOKEN_UID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCInsufficientFunds, NCInvalidSyscall
from hathor.nanocontracts.nc_types import NCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCDepositAction,
    NCGrantAuthorityAction,
    TokenUid,
    public,
)
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase

CONTRACT_NC_TYPE = make_nc_type(ContractId)
BLUEPRINT_NC_TYPE = make_nc_type(BlueprintId)
OPT_CONTRACT_NC_TYPE: NCType[ContractId | None] = make_nc_type(ContractId | None)  # type: ignore[arg-type]
OPT_BLUEPRINT_NC_TYPE: NCType[BlueprintId | None] = make_nc_type(BlueprintId | None)  # type: ignore[arg-type]


class MyBlueprint(Blueprint):
    my_nc_id: ContractId
    my_blueprint_id: BlueprintId

    other_nc_id: Optional[ContractId]
    other_blueprint_id: Optional[BlueprintId]

    @public
    def initialize(self, ctx: Context, other_nc_id: ContractId) -> None:
        self.my_nc_id = self.syscall.get_contract_id()
        self.my_blueprint_id = self.syscall.get_blueprint_id()

        self.other_nc_id = other_nc_id
        self.other_blueprint_id = self.syscall.get_blueprint_id(other_nc_id)


class OtherBlueprint(Blueprint):
    @public(allow_deposit=True, allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_grant_authority=True)
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def revoke(self, ctx: Context, token_uid: TokenUid, revoke_mint: bool, revoke_melt: bool) -> None:
        self.syscall.revoke_authorities(token_uid, revoke_mint=revoke_mint, revoke_melt=revoke_melt)

    @public
    def mint(self, ctx: Context, token_uid: TokenUid, amount: int) -> None:
        self.syscall.mint_tokens(token_uid, amount=amount)

    @public
    def melt(self, ctx: Context, token_uid: TokenUid, amount: int) -> None:
        self.syscall.melt_tokens(token_uid, amount=amount)

    @public(allow_deposit=True, allow_grant_authority=True)
    def create_tokens(self, ctx: Context, amount: int) -> TokenUid:
        return self.syscall.create_deposit_token(
            token_name='Dbt',
            token_symbol='Dbt',
            amount=amount,
            melt_authority=False,
            mint_authority=False
        )


class FeeTokenBlueprint(Blueprint):
    created_fee_token_uid: TokenUid

    @public(allow_deposit=True, allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_grant_authority=True)
    def create_fee_token(self, ctx: Context, name: str, symbol: str, amount: int,
                         fee_payment_token: TokenUid) -> TokenUid:
        token_uid = self.syscall.create_fee_token(
            name,
            symbol,
            amount,
            True,
            True,
            fee_payment_token=fee_payment_token)
        self.created_fee_token_uid = token_uid
        return token_uid

    @public(allow_deposit=True, allow_grant_authority=True)
    def create_deposit_token(self, ctx: Context, name: str, symbol: str, amount: int) -> TokenUid:
        return self.syscall.create_deposit_token(name, symbol, amount)

    @public(allow_deposit=True)
    def mint(self, ctx: Context, amount: int, fee_payment_token: TokenUid) -> None:
        self.syscall.mint_tokens(self.created_fee_token_uid, amount=amount, fee_payment_token=fee_payment_token)

    @public(allow_deposit=True)
    def melt(self, ctx: Context, amount: int, fee_payment_token: TokenUid) -> None:
        self.syscall.melt_tokens(self.created_fee_token_uid, amount=amount, fee_payment_token=fee_payment_token)


class NCNanoContractTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.my_blueprint_id = self.gen_random_blueprint_id()
        self.other_blueprint_id = self.gen_random_blueprint_id()
        self.fee_blueprint_id = self.gen_random_blueprint_id()

        self.nc_catalog.blueprints[self.my_blueprint_id] = MyBlueprint
        self.nc_catalog.blueprints[self.other_blueprint_id] = OtherBlueprint
        self.nc_catalog.blueprints[self.fee_blueprint_id] = FeeTokenBlueprint

    def test_basics(self) -> None:
        nc1_id = self.gen_random_contract_id()
        nc2_id = self.gen_random_contract_id()

        ctx = self.create_context()
        self.runner.create_contract(nc1_id, self.other_blueprint_id, ctx)
        self.runner.create_contract(nc2_id, self.my_blueprint_id, ctx, nc1_id)

        storage2 = self.runner.get_storage(nc2_id)

        assert storage2.get_obj(b'my_nc_id', CONTRACT_NC_TYPE) == nc2_id
        assert storage2.get_obj(b'other_nc_id', OPT_CONTRACT_NC_TYPE) == nc1_id

        assert storage2.get_obj(b'my_blueprint_id', BLUEPRINT_NC_TYPE) == self.my_blueprint_id
        assert storage2.get_obj(b'other_blueprint_id', OPT_BLUEPRINT_NC_TYPE) == self.other_blueprint_id

    def test_authorities(self) -> None:
        nc_id = self.gen_random_contract_id()

        ctx_initialize = self.create_context(
            actions=[
                NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=1000),
            ],
        )
        self.runner.create_contract(nc_id, self.other_blueprint_id, ctx_initialize)

        storage = self.runner.get_storage(nc_id)

        ctx_create = self.create_context(
            actions=[NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=10),],
        )
        dbt_token_uid = self.runner.call_public_method(nc_id, 'create_tokens', ctx_create, 1000)
        htr_balance_key = BalanceKey(nc_id=nc_id, token_uid=HATHOR_TOKEN_UID)
        dbt_balance_key = BalanceKey(nc_id=nc_id, token_uid=dbt_token_uid)

        ctx_grant = self.create_context(
            actions=[NCGrantAuthorityAction(token_uid=dbt_token_uid, mint=True, melt=True)],
            vertex=self.get_genesis_tx(),
            caller_id=self.gen_random_address(),
            timestamp=0,
        )
        self.runner.call_public_method(nc_id, 'nop', ctx_grant)

        ctx = self.create_context(
            actions=[],
            vertex=self.get_genesis_tx(),
            caller_id=self.gen_random_address(),
            timestamp=0,
        )

        # Starting state
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            dbt_balance_key: Balance(value=1000, can_mint=True, can_melt=True),
        }

        # After mint
        self.runner.call_public_method(nc_id, 'mint', ctx, dbt_token_uid, 123)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=998, can_mint=False, can_melt=False),
            dbt_balance_key: Balance(value=1123, can_mint=True, can_melt=True),
        }

        # After melt
        self.runner.call_public_method(nc_id, 'melt', ctx, dbt_token_uid, 456)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1002, can_mint=False, can_melt=False),
            dbt_balance_key: Balance(value=667, can_mint=True, can_melt=True),
        }

        # After revoke mint
        self.runner.call_public_method(nc_id, 'revoke', ctx, dbt_token_uid, True, False)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1002, can_mint=False, can_melt=False),
            dbt_balance_key: Balance(value=667, can_mint=False, can_melt=True),
        }

        # After revoke melt
        self.runner.call_public_method(nc_id, 'revoke', ctx, dbt_token_uid, False, True)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1002, can_mint=False, can_melt=False),
            dbt_balance_key: Balance(value=667, can_mint=False, can_melt=False),
        }

        # Try revoke mint without having the authority
        msg = f'contract {nc_id.hex()} cannot mint {dbt_token_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'revoke', ctx, dbt_token_uid, True, False)

        # Try revoke melt without having the authority
        msg = f'contract {nc_id.hex()} cannot melt {dbt_token_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'revoke', ctx, dbt_token_uid, False, True)

        # Try mint TKA
        msg = f'contract {nc_id.hex()} cannot mint {dbt_token_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'mint', ctx, dbt_token_uid, 123)

        # Try melt TKA
        msg = f'contract {nc_id.hex()} cannot melt {dbt_token_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'melt', ctx, dbt_token_uid, 456)

        # Try mint HTR
        with pytest.raises(NCInvalidSyscall, match=f'contract {nc_id.hex()} cannot mint HTR tokens'):
            self.runner.call_public_method(nc_id, 'mint', ctx, HATHOR_TOKEN_UID, 123)

        # Try melt HTR
        with pytest.raises(NCInvalidSyscall, match=f'contract {nc_id.hex()} cannot melt HTR tokens'):
            self.runner.call_public_method(nc_id, 'melt', ctx, HATHOR_TOKEN_UID, 456)

        # Try revoke HTR authorities
        with pytest.raises(NCInvalidSyscall, match=f'contract {nc_id.hex()} cannot revoke authorities from HTR token'):
            self.runner.call_public_method(nc_id, 'revoke', ctx, HATHOR_TOKEN_UID, True, False)

        # Final state
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1002, can_mint=False, can_melt=False),
            dbt_balance_key: Balance(value=667, can_mint=False, can_melt=False),
        }

    def test_fee_token_creation(self) -> None:
        nc_id = self.gen_random_contract_id()

        ctx_initialize = self.create_context([], self.get_genesis_tx())

        self.runner.create_contract(nc_id, self.fee_blueprint_id, ctx_initialize)
        storage = self.runner.get_storage(nc_id)

        # Starting state
        assert storage.get_all_balances() == {}

        ctx_create_token = self.create_context(
            [NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=2)],
            self.get_genesis_tx()
        )

        token_uid = self.runner.call_public_method(nc_id, 'create_fee_token', ctx_create_token,
                                                   'FeeToken', 'FBT', 1000000, TokenUid(HATHOR_TOKEN_UID))

        htr_balance_key = BalanceKey(nc_id=nc_id, token_uid=HATHOR_TOKEN_UID)
        fbt_balance_key = BalanceKey(nc_id=nc_id, token_uid=token_uid)

        # fee token creation charging 1 HTR
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
        }

        ctx_create_deposit_token = self.create_context()
        dbt_token_uid = self.runner.call_public_method(nc_id, 'create_deposit_token',
                                                       ctx_create_deposit_token, 'DepositToken', 'DBT', 100)

        dbt_balance_key = BalanceKey(nc_id=nc_id, token_uid=dbt_token_uid)

        # deposit token creation charging 1 HTR
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=100, can_mint=True, can_melt=True),
        }

        fbt_token2_uid = self.runner.call_public_method(nc_id, 'create_fee_token', self.create_context(),
                                                        'FeeToken2', 'FB2', 1000000, dbt_token_uid)
        fbt2_balance_key = BalanceKey(nc_id=nc_id, token_uid=fbt_token2_uid)

        # created fee token paying with deposit token
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=0, can_mint=True, can_melt=True),
            fbt2_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
        }

        # Try to create fee tokens without enough dbt balances
        msg = f'negative balance for contract {nc_id.hex()}'
        with pytest.raises(NCInsufficientFunds, match=msg):
            self.runner.call_public_method(nc_id, 'create_fee_token', self.create_context(),
                                           'FeeToken3', 'FB3', 1000000, dbt_token_uid)

        # Try to create fee tokens without enough dbt balances
        msg = f'negative balance for contract {nc_id.hex()}'
        with pytest.raises(NCInsufficientFunds, match=msg):
            self.runner.call_public_method(nc_id, 'create_fee_token', self.create_context(),
                                           'FeeToken3', 'FB3', 1000000, TokenUid(HATHOR_TOKEN_UID))

        # created fee token paying with deposit token
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=0, can_mint=True, can_melt=True),
            fbt2_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
        }

    def test_fee_token_melt(self) -> None:
        nc_id = self.gen_random_contract_id()

        ctx_initialize = self.create_context([], self.get_genesis_tx())

        self.runner.create_contract(nc_id, self.fee_blueprint_id, ctx_initialize)
        storage = self.runner.get_storage(nc_id)

        # Starting state
        assert storage.get_all_balances() == {}

        # Create a fee token first so we have something to melt
        ctx_create_token = self.create_context(
            [NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=2)],
            self.get_genesis_tx()
        )

        token_uid = self.runner.call_public_method(nc_id, 'create_fee_token', ctx_create_token,
                                                   'FeeToken', 'FBT', 1000000, TokenUid(HATHOR_TOKEN_UID))

        htr_balance_key = BalanceKey(nc_id=nc_id, token_uid=HATHOR_TOKEN_UID)
        fbt_balance_key = BalanceKey(nc_id=nc_id, token_uid=token_uid)

        ctx_create_deposit_token = self.create_context()
        dbt_token_uid = self.runner.call_public_method(nc_id, 'create_deposit_token',
                                                       ctx_create_deposit_token, 'DepositToken', 'DBT', 100)

        dbt_balance_key = BalanceKey(nc_id=nc_id, token_uid=dbt_token_uid)

        # fee token creation charging 1 HTR, creating 1000000 tokens
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=100, can_mint=True, can_melt=True),
        }

        # Successfully melt some tokens - don't deposit, melt from existing balance using deposit token
        self.runner.call_public_method(nc_id, 'melt', self.create_context(), 500000, dbt_token_uid)

        # Balance should decrease by melted amount, HTR consumed for fee
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=500000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=0, can_mint=True, can_melt=True),
        }

        # Try to melt more tokens - should fail due to insufficient HTR for fee payment
        msg = f'negative balance for contract {nc_id.hex()}'
        with pytest.raises(NCInsufficientFunds, match=msg):
            self.runner.call_public_method(nc_id, 'melt', self.create_context(), 1, TokenUid(HATHOR_TOKEN_UID))

        # Balance should remain unchanged after failed melt attempt
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=500000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=0, can_mint=True, can_melt=True),
        }

    def test_fee_token_mint(self) -> None:
        nc_id = self.gen_random_contract_id()

        ctx_initialize = self.create_context([], self.get_genesis_tx())

        self.runner.create_contract(nc_id, self.fee_blueprint_id, ctx_initialize)
        storage = self.runner.get_storage(nc_id)

        # Starting state
        assert storage.get_all_balances() == {}

        # Create a fee token first so we have something to mint to
        ctx_create_token = self.create_context(
            [NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=6)],
            self.get_genesis_tx()
        )

        token_uid = self.runner.call_public_method(nc_id, 'create_fee_token', ctx_create_token,
                                                   'FeeToken', 'FBT', 1000000, TokenUid(HATHOR_TOKEN_UID))

        # Create a deposit token to use as fee payment
        dbt_token_uid = self.runner.call_public_method(nc_id, 'create_deposit_token', self.create_context(),
                                                       'DepositToken', 'DBT', 500)

        htr_balance_key = BalanceKey(nc_id=nc_id, token_uid=HATHOR_TOKEN_UID)
        fbt_balance_key = BalanceKey(nc_id=nc_id, token_uid=token_uid)
        dbt_balance_key = BalanceKey(nc_id=nc_id, token_uid=dbt_token_uid)

        # After token creation: HTR consumed by token creation fees and deposit amounts
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1000000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=500, can_mint=True, can_melt=True),
        }

        # Successfully mint tokens using deposit token as fee payment (no HTR left)
        self.runner.call_public_method(nc_id, 'mint', self.create_context(), 100000, dbt_token_uid)

        # Balance should increase by minted amount, deposit token consumed for fee
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1100000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=400, can_mint=True, can_melt=True),
        }

        # Successfully mint more tokens using deposit token as fee payment
        self.runner.call_public_method(nc_id, 'mint', self.create_context(), 200000, dbt_token_uid)

        # Balance should increase, deposit token consumed for fee
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1300000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=300, can_mint=True, can_melt=True),
        }

        # Drain remaining deposit tokens
        self.runner.call_public_method(nc_id, 'mint', self.create_context(), 50000, dbt_token_uid)
        self.runner.call_public_method(nc_id, 'mint', self.create_context(), 50000, dbt_token_uid)
        self.runner.call_public_method(nc_id, 'mint', self.create_context(), 50000, dbt_token_uid)

        # All deposit tokens should be consumed
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1450000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=0, can_mint=True, can_melt=True),
        }

        # Try to mint with insufficient deposit tokens for fee payment - should fail
        msg = f'negative balance for contract {nc_id.hex()}'
        with pytest.raises(NCInsufficientFunds, match=msg):
            self.runner.call_public_method(nc_id, 'mint', self.create_context(), 1, dbt_token_uid)

        # Try to mint with insufficient HTR for fee payment - should also fail
        with pytest.raises(NCInsufficientFunds, match=msg):
            self.runner.call_public_method(nc_id, 'mint', self.create_context(), 1, TokenUid(HATHOR_TOKEN_UID))

        # Balance should remain unchanged after failed mint attempts
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=0, can_mint=False, can_melt=False),
            fbt_balance_key: Balance(value=1450000, can_mint=True, can_melt=True),
            dbt_balance_key: Balance(value=0, can_mint=True, can_melt=True),
        }
