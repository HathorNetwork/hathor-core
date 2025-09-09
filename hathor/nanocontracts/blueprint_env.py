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

from typing import TYPE_CHECKING, Any, Collection, Optional, Sequence, final

from hathor.nanocontracts.storage import NCContractStorage
from hathor.nanocontracts.types import Amount, BlueprintId, ContractId, NCAction, TokenUid

if TYPE_CHECKING:
    from hathor.nanocontracts.contract_accessor import ContractAccessor
    from hathor.nanocontracts.nc_exec_logs import NCLogger
    from hathor.nanocontracts.rng import NanoRNG
    from hathor.nanocontracts.runner import Runner
    from hathor.nanocontracts.types import NCArgs


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
        # XXX: we could replace dict|None with a Cache that can be disabled, cleared, limited, etc
        self.__cache__: dict[str, Any] | None = None if disable_cache else {}

    @final
    @property
    def rng(self) -> NanoRNG:
        """Return an RNG for the current contract."""
        return self.__runner.syscall_get_rng()

    @final
    def get_contract_id(self) -> ContractId:
        """Return the current contract id."""
        return self.__runner.get_current_contract_id()

    @final
    def get_blueprint_id(self, contract_id: Optional[ContractId] = None) -> BlueprintId:
        """Return the blueprint id of a nano contract. By default, it returns for the current contract."""
        if contract_id is None:
            contract_id = self.get_contract_id()
        return self.__runner.get_blueprint_id(contract_id)

    def get_balance_before_current_call(
        self,
        token_uid: Optional[TokenUid] = None,
        *,
        contract_id: Optional[ContractId] = None,
    ) -> Amount:
        """
        Return the balance for a given token before the current call, that is,
        excluding any actions and changes in the current call.

        For instance, if a contract has 50 HTR and the call is requesting to withdraw 3 HTR,
        then this method will return 50 HTR."""
        balance = self.__runner.get_balance_before_current_call(contract_id, token_uid)
        return Amount(balance.value)

    def get_current_balance(
        self,
        token_uid: Optional[TokenUid] = None,
        *,
        contract_id: Optional[ContractId] = None,
    ) -> Amount:
        """
        Return the current balance for a given token, which includes all actions and changes in the current call.

        For instance, if a contract has 50 HTR and the call is requesting to withdraw 3 HTR,
        then this method will return 47 HTR.
        """
        balance = self.__runner.get_current_balance(contract_id, token_uid)
        return Amount(balance.value)

    @final
    def can_mint_before_current_call(
        self,
        token_uid: TokenUid,
        *,
        contract_id: Optional[ContractId] = None,
    ) -> bool:
        """
        Return whether a given token could be minted before the current call, that is,
        excluding any actions and changes in the current call.

        For instance, if a contract has a mint authority and a call is revoking it,
        then this method will return `True`.
        """
        balance = self.__runner.get_balance_before_current_call(contract_id, token_uid)
        return balance.can_mint

    @final
    def can_mint(
        self,
        token_uid: TokenUid,
        *,
        contract_id: Optional[ContractId] = None,
    ) -> bool:
        """
        Return whether a given token can currently be minted,
        which includes all actions and changes in the current call.

        For instance, if a contract has a mint authority and a call is revoking it,
        then this method will return `False`.
        """
        balance = self.__runner.get_current_balance(contract_id, token_uid)
        return balance.can_mint

    @final
    def can_melt_before_current_call(
        self,
        token_uid: TokenUid,
        *,
        contract_id: Optional[ContractId] = None,
    ) -> bool:
        """
        Return whether a given token could be melted before the current call, that is,
        excluding any actions and changes in the current call.

        For instance, if a contract has a melt authority and a call is revoking it,
        then this method will return `True`.
        """
        balance = self.__runner.get_balance_before_current_call(contract_id, token_uid)
        return balance.can_melt

    @final
    def can_melt(
        self,
        token_uid: TokenUid,
        *,
        contract_id: Optional[ContractId] = None,
    ) -> bool:
        """
        Return whether a given token can currently be melted,
        which includes all actions and changes in the current call.

        For instance, if a contract has a melt authority and a transaction is revoking it,
        then this method will return `False`.
        """
        balance = self.__runner.get_current_balance(contract_id, token_uid)
        return balance.can_melt

    @final
    def call_public_method(
        self,
        nc_id: ContractId,
        method_name: str,
        actions: Sequence[NCAction],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call a public method of another contract."""
        return self.__runner.syscall_call_another_contract_public_method(
            nc_id,
            method_name,
            actions,
            args,
            kwargs,
            forbid_fallback=False,
        )

    @final
    def proxy_call_public_method(
        self,
        blueprint_id: BlueprintId,
        method_name: str,
        actions: Sequence[NCAction],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute a proxy call to a public method of another blueprint."""
        return self.__runner.syscall_proxy_call_public_method(blueprint_id, method_name, actions, args, kwargs)

    @final
    def proxy_call_public_method_nc_args(
        self,
        blueprint_id: BlueprintId,
        method_name: str,
        actions: Sequence[NCAction],
        nc_args: NCArgs,
    ) -> Any:
        """Execute a proxy call to a public method of another blueprint."""
        return self.__runner.syscall_proxy_call_public_method_nc_args(blueprint_id, method_name, actions, nc_args)

    @final
    def call_view_method(self, nc_id: ContractId, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a view method of another contract."""
        return self.__runner.syscall_call_another_contract_view_method(nc_id, method_name, args, kwargs)

    @final
    def revoke_authorities(self, token_uid: TokenUid, *, revoke_mint: bool, revoke_melt: bool) -> None:
        """Revoke authorities from this nano contract."""
        self.__runner.syscall_revoke_authorities(token_uid=token_uid, revoke_mint=revoke_mint, revoke_melt=revoke_melt)

    @final
    def mint_tokens(self, token_uid: TokenUid, amount: int) -> None:
        """Mint tokens and add them to the balance of this nano contract."""
        self.__runner.syscall_mint_tokens(token_uid=token_uid, amount=amount)

    @final
    def melt_tokens(self, token_uid: TokenUid, amount: int) -> None:
        """Melt tokens by removing them from the balance of this nano contract."""
        self.__runner.syscall_melt_tokens(token_uid=token_uid, amount=amount)

    @final
    def create_contract(
        self,
        blueprint_id: BlueprintId,
        salt: bytes,
        actions: Sequence[NCAction],
        *args: Any,
        **kwargs: Any,
    ) -> tuple[ContractId, Any]:
        """Create a new contract."""
        return self.__runner.syscall_create_another_contract(blueprint_id, salt, actions, args, kwargs)

    @final
    def emit_event(self, data: bytes) -> None:
        """Emit a custom event from a Nano Contract."""
        self.__runner.syscall_emit_event(data)

    @final
    def create_deposit_token(
        self,
        token_name: str,
        token_symbol: str,
        amount: int,
        mint_authority: bool = True,
        melt_authority: bool = True,
        *,
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

    # XXX: temporary alias
    create_token = create_deposit_token

    @final
    def create_fee_token(
        self,
        token_name: str,
        token_symbol: str,
        amount: int,
        mint_authority: bool = True,
        melt_authority: bool = True,
        *,
        salt: bytes = b'',
    ) -> TokenUid:
        """Create a new fee-based token."""
        return self.__runner.syscall_create_child_fee_token(
            salt=salt,
            token_name=token_name,
            token_symbol=token_symbol,
            amount=amount,
            mint_authority=mint_authority,
            melt_authority=melt_authority,
        )

    @final
    def change_blueprint(self, blueprint_id: BlueprintId) -> None:
        """Change the blueprint of this contract."""
        self.__runner.syscall_change_blueprint(blueprint_id)

    @final
    def get_contract(
        self,
        contract_id: ContractId,
        *,
        blueprint_id: BlueprintId | Collection[BlueprintId] | None,
    ) -> ContractAccessor:
        """
        Get a contract accessor for the given contract ID.

        Args:
            contract_id: the ID of the contract.
            blueprint_id: the expected blueprint ID of the contract, or a collection of accepted blueprints,
                or None if any blueprint is accepted.

        """
        from hathor.nanocontracts.contract_accessor import ContractAccessor
        return ContractAccessor(runner=self.__runner, contract_id=contract_id, blueprint_id=blueprint_id)
