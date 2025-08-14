from typing import Optional

import pytest

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCInvalidSyscall
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
        self.syscall.mint_tokens(token_uid, amount)

    @public
    def melt(self, ctx: Context, token_uid: TokenUid, amount: int) -> None:
        self.syscall.melt_tokens(token_uid, amount)


class NCNanoContractTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.my_blueprint_id = self.gen_random_blueprint_id()
        self.other_blueprint_id = self.gen_random_blueprint_id()

        self.nc_catalog.blueprints[self.my_blueprint_id] = MyBlueprint
        self.nc_catalog.blueprints[self.other_blueprint_id] = OtherBlueprint

    def test_basics(self) -> None:
        nc1_id = self.gen_random_contract_id()
        nc2_id = self.gen_random_contract_id()

        tx = self.get_genesis_tx()

        ctx = Context([], tx, self.gen_random_address(), timestamp=0)
        self.runner.create_contract(nc1_id, self.other_blueprint_id, ctx)
        self.runner.create_contract(nc2_id, self.my_blueprint_id, ctx, nc1_id)

        storage2 = self.runner.get_storage(nc2_id)

        assert storage2.get_obj(b'my_nc_id', CONTRACT_NC_TYPE) == nc2_id
        assert storage2.get_obj(b'other_nc_id', OPT_CONTRACT_NC_TYPE) == nc1_id

        assert storage2.get_obj(b'my_blueprint_id', BLUEPRINT_NC_TYPE) == self.my_blueprint_id
        assert storage2.get_obj(b'other_blueprint_id', OPT_BLUEPRINT_NC_TYPE) == self.other_blueprint_id

    def test_authorities(self) -> None:
        nc_id = self.gen_random_contract_id()
        token_a_uid = self.gen_random_token_uid()
        htr_balance_key = BalanceKey(nc_id=nc_id, token_uid=HATHOR_TOKEN_UID)
        tka_balance_key = BalanceKey(nc_id=nc_id, token_uid=token_a_uid)

        ctx_initialize = Context(
            actions=[
                NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=1000),
                NCDepositAction(token_uid=token_a_uid, amount=1000),
            ],
            vertex=self.get_genesis_tx(),
            caller_id=self.gen_random_address(),
            timestamp=0,
        )

        self.runner.create_contract(nc_id, self.other_blueprint_id, ctx_initialize)
        storage = self.runner.get_storage(nc_id)

        ctx_grant = Context(
            actions=[NCGrantAuthorityAction(token_uid=token_a_uid, mint=True, melt=True)],
            vertex=self.get_genesis_tx(),
            caller_id=self.gen_random_address(),
            timestamp=0,
        )
        self.runner.call_public_method(nc_id, 'nop', ctx_grant)

        ctx = Context(
            actions=[],
            vertex=self.get_genesis_tx(),
            caller_id=self.gen_random_address(),
            timestamp=0,
        )

        # Starting state
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            tka_balance_key: Balance(value=1000, can_mint=True, can_melt=True),
        }

        # After mint
        self.runner.call_public_method(nc_id, 'mint', ctx, token_a_uid, 123)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=998, can_mint=False, can_melt=False),
            tka_balance_key: Balance(value=1123, can_mint=True, can_melt=True),
        }

        # After melt
        self.runner.call_public_method(nc_id, 'melt', ctx, token_a_uid, 456)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1002, can_mint=False, can_melt=False),
            tka_balance_key: Balance(value=667, can_mint=True, can_melt=True),
        }

        # After revoke mint
        self.runner.call_public_method(nc_id, 'revoke', ctx, token_a_uid, True, False)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1002, can_mint=False, can_melt=False),
            tka_balance_key: Balance(value=667, can_mint=False, can_melt=True),
        }

        # After revoke melt
        self.runner.call_public_method(nc_id, 'revoke', ctx, token_a_uid, False, True)
        assert storage.get_all_balances() == {
            htr_balance_key: Balance(value=1002, can_mint=False, can_melt=False),
            tka_balance_key: Balance(value=667, can_mint=False, can_melt=False),
        }

        # Try revoke mint without having the authority
        msg = f'contract {nc_id.hex()} cannot mint {token_a_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'revoke', ctx, token_a_uid, True, False)

        # Try revoke melt without having the authority
        msg = f'contract {nc_id.hex()} cannot melt {token_a_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'revoke', ctx, token_a_uid, False, True)

        # Try mint TKA
        msg = f'contract {nc_id.hex()} cannot mint {token_a_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'mint', ctx, token_a_uid, 123)

        # Try melt TKA
        msg = f'contract {nc_id.hex()} cannot melt {token_a_uid.hex()} tokens'
        with pytest.raises(NCInvalidSyscall, match=msg):
            self.runner.call_public_method(nc_id, 'melt', ctx, token_a_uid, 456)

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
            tka_balance_key: Balance(value=667, can_mint=False, can_melt=False),
        }
