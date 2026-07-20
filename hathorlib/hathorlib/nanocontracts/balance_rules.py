# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

from typing_extensions import assert_never, override

from hathorlib.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathorlib.nanocontracts.exception import NCInvalidAction
from hathorlib.nanocontracts.storage import NCChangesTracker
from hathorlib.nanocontracts.types import (
    BaseAction,
    NCAcquireAuthorityAction,
    NCAction,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCWithdrawalAction,
)
from hathorlib.token_amount_version import TokenAmountVersion
from hathorlib.token_info import TokenVersion

if TYPE_CHECKING:
    from hathor.transaction.token_info import TokenInfoDict  # type: ignore[import-not-found]

T = TypeVar('T', bound=BaseAction)


class BalanceRules(ABC, Generic[T]):
    """
    An abstract base class that unifies balance rules for NCActions.

    Requires definitions for a verification-phase rule and two nano contract execution-phase rules, one for the callee,
    which is always a contract, and one for the caller, which may be a transaction or another contract.
    """

    __slots__ = ('settings', 'action', 'token_amount_version')

    def __init__(self, settings: HathorSettings, action: T, token_amount_version: TokenAmountVersion) -> None:
        self.settings = settings
        self.action = action
        self.token_amount_version = token_amount_version

    @abstractmethod
    def verification_rule(self, token_dict: TokenInfoDict) -> None:
        """
        Define how the respective action interacts with the transaction's
        token_dict during the verification phase, updating it.
        """
        raise NotImplementedError

    @abstractmethod
    def nc_callee_execution_rule(self, callee_changes_tracker: NCChangesTracker) -> None:
        """
        Define how the respective action interacts with the transaction's changes tracker during nano contract
        execution, updating it, on the callee side.
        """
        raise NotImplementedError

    @abstractmethod
    def nc_cross_call_execution_rule(
        self,
        *,
        caller_changes_tracker: NCChangesTracker,
        callee_changes_tracker: NCChangesTracker,
    ) -> None:
        """
        Define how the respective action interacts with the transaction's changes tracker during nano contract
        execution, updating it, on both the caller and callee side — that is, when a contract calls another contract.
        """
        raise NotImplementedError

    @staticmethod
    def get_rules(
        settings: HathorSettings,
        action: NCAction,
        token_amount_version: TokenAmountVersion,
    ) -> BalanceRules:
        """Get the balance rules instance for the provided action."""
        match action:
            case NCDepositAction():
                return _DepositRules(settings, action, token_amount_version)
            case NCWithdrawalAction():
                return _WithdrawalRules(settings, action, token_amount_version)
            case NCGrantAuthorityAction():
                return _GrantAuthorityRules(settings, action, token_amount_version)
            case NCAcquireAuthorityAction():
                return _AcquireAuthorityRules(settings, action, token_amount_version)
            case _:
                assert_never(action)


class _DepositRules(BalanceRules[NCDepositAction]):
    """
    Define balance rules for the DEPOSIT action.

    - In the verification-phase, the amount is removed from the tx inputs/outputs balance.
    - In the execution-phase (callee), the amount is added to the nano contract balance.
    - In the execution-phase (caller), the amount is removed from the nano contract balance.
    """
    __slots__ = ()

    @override
    def verification_rule(self, token_dict: TokenInfoDict) -> None:
        token_info = token_dict[self.action.token_uid]
        token_info.amount = token_info.amount + self.action.amount
        token_dict[self.action.token_uid] = token_info

        if token_info.version == TokenVersion.FEE:
            token_info.chargeable_outputs += 1

    @override
    def nc_callee_execution_rule(self, callee_changes_tracker: NCChangesTracker) -> None:
        callee_changes_tracker.add_balance(self.action.token_uid, self.action.amount)

    @override
    def nc_cross_call_execution_rule(
        self,
        *,
        caller_changes_tracker: NCChangesTracker,
        callee_changes_tracker: NCChangesTracker,
    ) -> None:
        caller_changes_tracker.add_balance(self.action.token_uid, -self.action.amount)
        self.nc_callee_execution_rule(callee_changes_tracker)


class _WithdrawalRules(BalanceRules[NCWithdrawalAction]):
    """
    Define balance rules for the WITHDRAWAL action.

    - In the verification-phase, the amount is added to the tx inputs/outputs balance.
    - In the execution-phase (callee), the amount is removed from the nano contract balance.
    - In the execution-phase (caller), the amount is added to the nano contract balance.
    """
    __slots__ = ()

    @override
    def verification_rule(self, token_dict: TokenInfoDict) -> None:
        token_info = token_dict[self.action.token_uid]
        token_info.amount = token_info.amount - self.action.amount
        token_dict[self.action.token_uid] = token_info

        if token_info.version == TokenVersion.FEE:
            token_info.chargeable_inputs += 1

    @override
    def nc_callee_execution_rule(self, callee_changes_tracker: NCChangesTracker) -> None:
        callee_changes_tracker.add_balance(self.action.token_uid, -self.action.amount)

    @override
    def nc_cross_call_execution_rule(
        self,
        *,
        caller_changes_tracker: NCChangesTracker,
        callee_changes_tracker: NCChangesTracker,
    ) -> None:
        caller_changes_tracker.add_balance(self.action.token_uid, self.action.amount)
        self.nc_callee_execution_rule(callee_changes_tracker)


class _GrantAuthorityRules(BalanceRules[NCGrantAuthorityAction]):
    """
    Define balance rules for the GRANT_AUTHORITY action.

    - In the verification phase, we check whether the tx inputs can grant the authorities to the nano contract.
    - In the execution phase (callee), the authorities are granted to the nano contract.
    - In the execution phase (caller), we check whether the balance can grant the authorities to the called contract.
    """
    __slots__ = ()

    @override
    def verification_rule(self, token_dict: TokenInfoDict) -> None:
        assert self.action.token_uid != HATHOR_TOKEN_UID
        token_info = token_dict[self.action.token_uid]
        if self.action.mint and not token_info.can_mint:
            raise NCInvalidAction(
                f'{self.action.name} token {self.action.token_uid.hex()} requires mint, but no input has it'
            )

        if self.action.melt and not token_info.can_melt:
            raise NCInvalidAction(
                f'{self.action.name} token {self.action.token_uid.hex()} requires melt, but no input has it'
            )

    @override
    def nc_callee_execution_rule(self, callee_changes_tracker: NCChangesTracker) -> None:
        assert self.action.token_uid != HATHOR_TOKEN_UID
        callee_changes_tracker.grant_authorities(
            self.action.token_uid,
            grant_mint=self.action.mint,
            grant_melt=self.action.melt,
        )

    @override
    def nc_cross_call_execution_rule(
        self,
        *,
        caller_changes_tracker: NCChangesTracker,
        callee_changes_tracker: NCChangesTracker,
    ) -> None:
        if self.action.token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidAction('cannot grant authorities for HTR token')

        balance = caller_changes_tracker.get_balance(self.action.token_uid)

        if self.action.mint and not balance.can_mint:
            raise NCInvalidAction(
                f'{self.action.name} token {self.action.token_uid.hex()} requires mint, '
                f'but contract does not have that authority'
            )

        if self.action.melt and not balance.can_melt:
            raise NCInvalidAction(
                f'{self.action.name} token {self.action.token_uid.hex()} requires melt, '
                f'but contract does not have that authority'
            )

        self.nc_callee_execution_rule(callee_changes_tracker)


class _AcquireAuthorityRules(BalanceRules[NCAcquireAuthorityAction]):
    """
    Define balance rules for the ACQUIRE_AUTHORITY action.

    - In the verification phase, we allow the respective authorities in the transaction's token_info.
    - In the execution phase (callee), we check whether the nano contract balance can grant those authorities.
    - In the execution phase (caller), we grant the authorities to the caller.
    """
    __slots__ = ()

    @override
    def verification_rule(self, token_dict: TokenInfoDict) -> None:
        assert self.action.token_uid != HATHOR_TOKEN_UID
        token_info = token_dict[self.action.token_uid]
        token_info.can_mint = token_info.can_mint or self.action.mint
        token_info.can_melt = token_info.can_melt or self.action.melt
        token_dict[self.action.token_uid] = token_info

    @override
    def nc_callee_execution_rule(self, callee_changes_tracker: NCChangesTracker) -> None:
        assert self.action.token_uid != HATHOR_TOKEN_UID
        balance = callee_changes_tracker.get_balance(self.action.token_uid)

        if self.action.mint and not balance.can_mint:
            raise NCInvalidAction(f'cannot acquire mint authority for token {self.action.token_uid.hex()}')

        if self.action.melt and not balance.can_melt:
            raise NCInvalidAction(f'cannot acquire melt authority for token {self.action.token_uid.hex()}')

    @override
    def nc_cross_call_execution_rule(
        self,
        caller_changes_tracker: NCChangesTracker,
        callee_changes_tracker: NCChangesTracker,
    ) -> None:
        if self.action.token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidAction('cannot acquire authorities for HTR token')

        self.nc_callee_execution_rule(callee_changes_tracker)
        caller_changes_tracker.grant_authorities(
            self.action.token_uid,
            grant_mint=self.action.mint,
            grant_melt=self.action.melt,
        )
