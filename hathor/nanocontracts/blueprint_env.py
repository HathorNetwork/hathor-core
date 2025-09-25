#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Collection, Sequence, TypeAlias, final

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.types import Amount, BlueprintId, ContractId, NCAction, NCFee, TokenUid

if TYPE_CHECKING:
    from hathor.nanocontracts.contract_accessor import ContractAccessor
    from hathor.nanocontracts.initialize_method_accessor import InitializeMethodAccessor
    from hathor.nanocontracts.nc_exec_logs import NCLogger
    from hathor.nanocontracts.proxy_accessor import ProxyAccessor
    from hathor.nanocontracts.rng import NanoRNG
    from hathor.nanocontracts.runner import Runner
    from hathor.nanocontracts.storage import NCContractStorage
    from hathor.nanocontracts.types import Address


NCAttrCache: TypeAlias = dict[bytes, Any] | None


@final
class BlueprintEnvironment:
    """A class that holds all possible interactions a blueprint may have with the system."""

    __slots__ = ('__runner', '__log__', '__storage__', '__cache__')

    def __init__(
        self,
        runner: Runner,
        nc_logger: NCLogger,
        storage: NCContractStorage,
        *,
        disable_cache: bool = False,
    ) -> None:
        self.__log__ = nc_logger
        self.__runner = runner
        self.__storage__ = storage
        # XXX: we could replace dict|None with a cache class that can be disabled, cleared, limited, etc
        self.__cache__: NCAttrCache = None if disable_cache else {}

    @property
    def rng(self) -> NanoRNG:
        """Return an RNG for the current contract."""
        return self.__runner.syscall_get_rng()

    def get_contract_id(self) -> ContractId:
        """Return the ContractId of the current nano contract."""
        return self.__runner.get_current_contract_id()

    def get_blueprint_id(self) -> BlueprintId:
        """
        Return the BlueprintId of the current nano contract.

        This means that during a proxy call, this method will return the BlueprintId of the caller's blueprint,
        NOT the BlueprintId of the Blueprint that owns the running code.
        """
        contract_id = self.get_contract_id()
        return self.__runner.get_blueprint_id(contract_id)

    def get_current_code_blueprint_id(self) -> BlueprintId:
        """
        Return the BlueprintId of the Blueprint that owns the currently running code.

        This means that during a proxy call, this method will return the BlueprintId of the Blueprint that owns the
        running code, NOT the BlueprintId of the current nano contract.
        """
        return self.__runner.get_current_code_blueprint_id()

    def get_balance_before_current_call(self, token_uid: TokenUid | None = None) -> Amount:
        """
        Return the balance for a given token before the current call, that is,
        excluding any actions and changes in the current call.

        For instance, if a contract has 50 HTR and the call is requesting to withdraw 3 HTR,
        then this method will return 50 HTR."""
        contract_id = self.get_contract_id()
        balance = self.__runner.get_balance_before_current_call(contract_id, token_uid)
        return Amount(balance.value)

    def get_current_balance(self, token_uid: TokenUid | None = None) -> Amount:
        """
        Return the current balance for a given token, which includes all actions and changes in the current call.

        For instance, if a contract has 50 HTR and the call is requesting to withdraw 3 HTR,
        then this method will return 47 HTR.
        """
        contract_id = self.get_contract_id()
        balance = self.__runner.get_current_balance(contract_id, token_uid)
        return Amount(balance.value)

    def can_mint_before_current_call(self, token_uid: TokenUid) -> bool:
        """
        Return whether a given token could be minted before the current call, that is,
        excluding any actions and changes in the current call.

        For instance, if a contract has a mint authority and a call is revoking it,
        then this method will return `True`.
        """
        contract_id = self.get_contract_id()
        balance = self.__runner.get_balance_before_current_call(contract_id, token_uid)
        return balance.can_mint

    def can_mint(self, token_uid: TokenUid) -> bool:
        """
        Return whether a given token can currently be minted,
        which includes all actions and changes in the current call.

        For instance, if a contract has a mint authority and a call is revoking it,
        then this method will return `False`.
        """
        contract_id = self.get_contract_id()
        balance = self.__runner.get_current_balance(contract_id, token_uid)
        return balance.can_mint

    def can_melt_before_current_call(self, token_uid: TokenUid) -> bool:
        """
        Return whether a given token could be melted before the current call, that is,
        excluding any actions and changes in the current call.

        For instance, if a contract has a melt authority and a call is revoking it,
        then this method will return `True`.
        """
        contract_id = self.get_contract_id()
        balance = self.__runner.get_balance_before_current_call(contract_id, token_uid)
        return balance.can_melt

    def can_melt(self, token_uid: TokenUid) -> bool:
        """
        Return whether a given token can currently be melted,
        which includes all actions and changes in the current call.

        For instance, if a contract has a melt authority and a transaction is revoking it,
        then this method will return `False`.
        """
        contract_id = self.get_contract_id()
        balance = self.__runner.get_current_balance(contract_id, token_uid)
        return balance.can_melt

    def revoke_authorities(self, token_uid: TokenUid, *, revoke_mint: bool, revoke_melt: bool) -> None:
        """Revoke authorities from this nano contract."""
        self.__runner.syscall_revoke_authorities(token_uid=token_uid, revoke_mint=revoke_mint, revoke_melt=revoke_melt)

    def mint_tokens(
        self,
        token_uid: TokenUid,
        amount: int,
        *,
        fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)
    ) -> None:
        """Mint tokens and add them to the balance of this nano contract."""
        self.__runner.syscall_mint_tokens(token_uid=token_uid, amount=amount, fee_payment_token=fee_payment_token)

    def melt_tokens(
        self,
        token_uid: TokenUid,
        amount: int,
        *,
        fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)
    ) -> None:
        """Melt tokens by removing them from the balance of this nano contract."""
        self.__runner.syscall_melt_tokens(token_uid=token_uid, amount=amount, fee_payment_token=fee_payment_token)

    def emit_event(self, data: bytes) -> None:
        """Emit a custom event from a Nano Contract."""
        self.__runner.syscall_emit_event(data)

    def create_deposit_token(
        self,
        *,
        token_name: str,
        token_symbol: str,
        amount: int,
        mint_authority: bool = True,
        melt_authority: bool = True,
        salt: bytes = b'',
    ) -> TokenUid:
        """Create a new deposit-based token."""
        return self.__runner.syscall_create_child_deposit_token(
            salt=salt,
            token_name=token_name,
            token_symbol=token_symbol,
            amount=amount,
            mint_authority=mint_authority,
            melt_authority=melt_authority,
        )

    def create_fee_token(
        self,
        *,
        token_name: str,
        token_symbol: str,
        amount: int,
        mint_authority: bool = True,
        melt_authority: bool = True,
        salt: bytes = b'',
        fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)
    ) -> TokenUid:
        """Create a new fee-based token."""
        return self.__runner.syscall_create_child_fee_token(
            salt=salt,
            token_name=token_name,
            token_symbol=token_symbol,
            amount=amount,
            mint_authority=mint_authority,
            melt_authority=melt_authority,
            fee_payment_token=fee_payment_token
        )

    def change_blueprint(self, blueprint_id: BlueprintId) -> None:
        """Change the blueprint of this contract."""
        self.__runner.syscall_change_blueprint(blueprint_id)

    def get_contract(
        self,
        contract_id: ContractId,
        *,
        blueprint_id: BlueprintId | Collection[BlueprintId] | None,
    ) -> ContractAccessor:
        """
        Get a contract accessor for the given contract ID. Use this for interacting with another contract.

        Args:
            contract_id: the ID of the contract.
            blueprint_id: the expected blueprint ID of the contract, or a collection of accepted blueprints,
                or None if any blueprint is accepted.

        """
        from hathor.nanocontracts.contract_accessor import ContractAccessor
        return ContractAccessor(runner=self.__runner, contract_id=contract_id, blueprint_id=blueprint_id)

    def get_proxy(self, blueprint_id: BlueprintId) -> ProxyAccessor:
        """
        Get a proxy accessor for the given blueprint ID. Use this for interacting with another blueprint via a proxy.
        """
        from hathor.nanocontracts.proxy_accessor import ProxyAccessor
        return ProxyAccessor(runner=self.__runner, blueprint_id=blueprint_id)

    def setup_new_contract(
        self,
        blueprint_id: BlueprintId,
        *actions: NCAction,
        fees: Sequence[NCFee] | None = None,
        salt: bytes,
    ) -> InitializeMethodAccessor:
        """Setup creation of a new contract."""
        from hathor.nanocontracts.initialize_method_accessor import InitializeMethodAccessor
        self.__runner.forbid_call_on_view('setup_new_contract')
        return InitializeMethodAccessor(
            runner=self.__runner,
            blueprint_id=blueprint_id,
            salt=salt,
            actions=actions,
            fees=fees or (),
        )

    def transfer_to_address(self, address: Address, amount: Amount, token: TokenUid) -> None:
        """Transfer a given amount of token to an address balance."""
        self.__runner.syscall_transfer_to_address(address, amount, token)
