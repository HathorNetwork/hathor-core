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

from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import Type, TypeAlias, TypeVar

from typing_extensions import Literal, assert_never

from hathor.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathor.nanocontracts.runner.types import (
    BaseSyscallUpdateTokensRecord,
    CallRecord,
    IndexUpdateRecordType,
    SyscallUpdateDepositTokensRecord,
    SyscallUpdateFeeTokensRecord,
)
from hathor.nanocontracts.storage import NCChangesTracker
from hathor.nanocontracts.types import TokenUid
from hathor.transaction.token_info import TokenVersion
from hathor.transaction.util import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount

T = TypeVar('T', bound=BaseSyscallUpdateTokensRecord)

AcceptedUpdateRecordType: TypeAlias = (
        Literal[IndexUpdateRecordType.MINT_TOKENS]
        | Literal[IndexUpdateRecordType.MELT_TOKENS]
        | Literal[IndexUpdateRecordType.CREATE_TOKEN]
    )


@dataclass(slots=True, kw_only=True)
class TokenSyscallBalanceEntry:
    token_uid: TokenUid
    amount: int


@dataclass(slots=True, kw_only=True)
class TokenSyscallBalance:
    type: AcceptedUpdateRecordType
    token: TokenSyscallBalanceEntry
    fee_payment: TokenSyscallBalanceEntry
    # create token syscall
    token_version: TokenVersion | None = None
    token_symbol: str | None = None
    token_name: str | None = None

    def to_syscall_record(self, record_class: Type[T]) -> T:
        """
        Factory method to create a syscall update record from a TokenSyscallBalance.

        This method provides a generic way to instantiate different types of
        BaseSyscallUpdateTokensRecord subclasses using the same operation data.

        Args:
            record_class: The class type to instantiate (e.g., SyscallUpdateDepositTokensRecord)

        Returns:
            An instance of the specified record class populated with operation data
        """
        return record_class(
            type=self.type,
            token_uid=self.token.token_uid,
            token_amount=self.token.amount,
            payment_token_uid=self.fee_payment.token_uid,
            payment_token_amount=self.fee_payment.amount,
            token_version=self.token_version,
            token_symbol=self.token_symbol,
            token_name=self.token_name,
        )


class TokenSyscallBalanceRules(ABC):
    """
    An abstract base class that unifies token balance rules for syscalls.

    Requires definitions for create tokens, mint, and melt syscalls.
    """

    __slots__ = ('_settings', 'token_version', 'token_uid')

    def __init__(
        self,
        settings: HathorSettings,
        token_uid: TokenUid,
        token_version: TokenVersion
    ) -> None:
        self._settings = settings
        self.token_version = token_version
        self.token_uid = token_uid

        assert token_uid != TokenUid(HATHOR_TOKEN_UID)
        assert token_version is not TokenVersion.NATIVE

    @abstractmethod
    def create_token(self,
                     token_uid: TokenUid,
                     token_symbol: str,
                     token_name: str,
                     amount: int,
                     fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)
                     ) -> TokenSyscallBalance:
        """
        Calculate and return the token amounts needed for token creation syscalls.

        Returns:
            dict[TokenUid, int]: A dictionary mapping token UIDs to their respective amounts
            that will be used by the Runner class for balance updates during token creation.
        """
        raise NotImplementedError

    @abstractmethod
    def mint(self, amount: int, *, fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)) -> TokenSyscallBalance:
        """
        Calculate and return the token amounts needed for minting operations.

        Args:
            amount: The amount to be minted.
            fee_payment_token: The token that will be used to pay fees

        Returns:
            TokenSyscallBalance: A data class with the current syscall record type, token UIDs, and
            their respective amounts that will be used by the Runner class for balance updates during token minting.
        """
        raise NotImplementedError

    @abstractmethod
    def melt(self, amount: int, *, fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)) -> TokenSyscallBalance:
        """
        Calculate and return the token amounts needed for melting operations.

        Args:
            amount: The amount to be melted.
            fee_payment_token: The token that will be used to pay fees

        Returns:
            TokenSyscallBalance: A data class with the current syscall record type, token UIDs, and
            their respective amounts that will be used by the Runner class for balance updates during token melting.
        """
        raise NotImplementedError

    @abstractmethod
    def get_syscall_update_token_record(self,
                                        syscall_balance: TokenSyscallBalance
                                        ) -> SyscallUpdateDepositTokensRecord | SyscallUpdateFeeTokensRecord:
        """
        Create a syscall update record for the given token operation.

        This method transforms a TokenSyscallBalance into the appropriate record type
        (SyscallUpdateDepositTokensRecord or SyscallUpdateFeeTokensRecord) that will
        be appended to the call record's index_updates for tracking token operations.

        Args:
            syscall_balance: The token balance operation containing operation type,
                           token amounts, and payment details.

        Returns:
            A syscall update record appropriate for the token version (deposit or fee).
        """
        raise NotImplementedError

    def update_tokens_amount(
        self,
        syscall_balance: TokenSyscallBalance,
        updated_tokens_totals:  defaultdict[TokenUid, int],
        call_record:  CallRecord,
        changes_tracker: NCChangesTracker
    ) -> None:
        """
        Update token balances and create index records for a token operation.

        This method performs the complete flow of updating token balances for syscalls:
        1. Updates the contract's token balances in the changes tracker
        2. Updates the global token totals
        3. Creates and appends the appropriate syscall record to call_record.index_updates

        Args:
            syscall_balance: The token balance operation containing token amounts and payment details
            updated_tokens_totals: Running total of token changes for the entire transaction
            call_record: The current call record where index updates will be appended
            changes_tracker: Tracks balance changes for the current contract

        Raises:
            AssertionError: If any of the required parameters are None
        """
        assert call_record.index_updates is not None
        assert changes_tracker is not None
        assert updated_tokens_totals is not None

        changes_tracker.add_balance(syscall_balance.token.token_uid, syscall_balance.token.amount)
        changes_tracker.add_balance(syscall_balance.fee_payment.token_uid, syscall_balance.fee_payment.amount)

        updated_tokens_totals[syscall_balance.token.token_uid] += syscall_balance.token.amount
        updated_tokens_totals[syscall_balance.fee_payment.token_uid] += syscall_balance.fee_payment.amount

        syscall_record = self.get_syscall_update_token_record(syscall_balance)
        call_record.index_updates.append(syscall_record)

    @staticmethod
    def get_rules(token_uid: TokenUid, token_version: TokenVersion,
                  settings: HathorSettings) -> TokenSyscallBalanceRules:
        """Get the balance rules instance for the provided token version."""
        match token_version:
            case TokenVersion.DEPOSIT:
                return _DepositTokenRules(
                    settings,
                    token_uid,
                    token_version,
                )
            case TokenVersion.FEE:
                return _FeeTokenRules(
                    settings,
                    token_uid,
                    token_version,
                )
            case TokenVersion.NATIVE:
                raise ValueError(f"NATIVE token version is not supported for token {token_uid.hex()}")
            case _:
                assert_never(token_version)


class _DepositTokenRules(TokenSyscallBalanceRules):

    def create_token(self,
                     token_uid: TokenUid,
                     token_symbol: str,
                     token_name: str,
                     amount: int,
                     fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID),
                     ) -> TokenSyscallBalance:
        htr_amount = -get_deposit_token_deposit_amount(self._settings, amount)

        return TokenSyscallBalance(
            type=IndexUpdateRecordType.CREATE_TOKEN,
            token_version=TokenVersion.DEPOSIT,
            token_name=token_name,
            token_symbol=token_symbol,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=fee_payment_token, amount=htr_amount)
        )

    def mint(self, amount: int, *, fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)) -> TokenSyscallBalance:
        htr_amount = -get_deposit_token_deposit_amount(self._settings, amount)

        return TokenSyscallBalance(
            type=IndexUpdateRecordType.MINT_TOKENS,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=fee_payment_token, amount=htr_amount)
        )

    def melt(self, amount: int, *, fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)) -> TokenSyscallBalance:
        htr_amount = +get_deposit_token_withdraw_amount(self._settings, amount)

        return TokenSyscallBalance(
            type=IndexUpdateRecordType.MELT_TOKENS,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=-amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=fee_payment_token, amount=htr_amount)
        )

    def get_syscall_update_token_record(self, operation: TokenSyscallBalance) -> SyscallUpdateDepositTokensRecord:
        return operation.to_syscall_record(SyscallUpdateDepositTokensRecord)


class _FeeTokenRules(TokenSyscallBalanceRules):

    def _get_fee_value(self, fee_payment_token: TokenUid) -> int:
        # For fee tokens, we only need to pay the transaction fee, not deposit HTR
        if fee_payment_token == TokenUid(HATHOR_TOKEN_UID):
            fee_amount = self._settings.FEE_PER_OUTPUT
        else:
            fee_amount = int(self._settings.FEE_PER_OUTPUT / self._settings.TOKEN_DEPOSIT_PERCENTAGE)

        return fee_amount * -1

    def create_token(self,
                     token_uid: TokenUid,
                     token_symbol: str,
                     token_name: str,
                     amount: int,
                     fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID),
                     ) -> TokenSyscallBalance:
        # For fee tokens, we only need to pay the transaction fee, not deposit HTR
        fee_amount = self._get_fee_value(fee_payment_token)

        return TokenSyscallBalance(
            type=IndexUpdateRecordType.CREATE_TOKEN,
            token_version=TokenVersion.FEE,
            token_name=token_name,
            token_symbol=token_symbol,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=fee_payment_token, amount=fee_amount)
        )

    def mint(self, amount: int, *, fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)) -> TokenSyscallBalance:
        fee_amount = self._get_fee_value(fee_payment_token)
        return TokenSyscallBalance(
            type=IndexUpdateRecordType.MINT_TOKENS,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=fee_payment_token, amount=fee_amount)
        )

    def melt(self, amount: int, *, fee_payment_token: TokenUid = TokenUid(HATHOR_TOKEN_UID)) -> TokenSyscallBalance:
        fee_amount = self._get_fee_value(fee_payment_token)
        return TokenSyscallBalance(
            type=IndexUpdateRecordType.MELT_TOKENS,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=-amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=fee_payment_token, amount=fee_amount)
        )

    def get_syscall_update_token_record(self, operation: TokenSyscallBalance) -> SyscallUpdateFeeTokensRecord:
        return operation.to_syscall_record(SyscallUpdateFeeTokensRecord)
