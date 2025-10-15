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
from dataclasses import dataclass
from enum import StrEnum, auto, unique

from typing_extensions import assert_never

from hathor.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathor.nanocontracts.exception import NCInvalidFeePaymentToken
from hathor.nanocontracts.runner.index_records import CreateTokenRecord, UpdateTokenBalanceRecord
from hathor.nanocontracts.types import TokenUid
from hathor.transaction.token_info import TokenDescription, TokenVersion
from hathor.transaction.util import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount


@unique
class TokenOperationType(StrEnum):
    """Types of token operations for syscalls."""
    CREATE = auto()
    MINT = auto()
    MELT = auto()


@dataclass(slots=True, kw_only=True)
class TokenSyscallBalanceEntry:
    token_uid: TokenUid
    amount: int


@dataclass(slots=True, kw_only=True)
class TokenSyscallBalance:
    type: TokenOperationType
    token: TokenSyscallBalanceEntry
    fee_payment: TokenSyscallBalanceEntry
    # create token syscall
    token_version: TokenVersion | None = None
    token_symbol: str | None = None
    token_name: str | None = None

    def to_syscall_records(self) -> list[UpdateTokenBalanceRecord | CreateTokenRecord]:
        """
        Convert TokenSyscallBalance to a list of UpdateTokenBalanceRecord or CreateTokenRecord.

        Each operation generates two records:
        1. Main token operation (mint/melt/create)
        2. Fee payment token operation

        Returns:
            A list with two index record instances.
        """
        records: list[UpdateTokenBalanceRecord | CreateTokenRecord] = []

        # First record: main token operation
        if self.token_version is not None:
            assert self.token_symbol is not None
            assert self.token_name is not None
            assert self.token_version != TokenVersion.NATIVE
            records.append(CreateTokenRecord(
                token_uid=self.token.token_uid,
                amount=self.token.amount,
                token_version=self.token_version,
                token_symbol=self.token_symbol,
                token_name=self.token_name,
            ))
        else:
            assert self.token_symbol is None
            assert self.token_name is None
            records.append(UpdateTokenBalanceRecord(token_uid=self.token.token_uid, amount=self.token.amount))

        # Second record: fee payment token
        records.append(UpdateTokenBalanceRecord(
            token_uid=self.fee_payment.token_uid,
            amount=self.fee_payment.amount,
        ))

        return records


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
    def create_token(
        self,
        *,
        token_uid: TokenUid,
        token_symbol: str,
        token_name: str,
        amount: int,
        fee_payment_token: TokenDescription
    ) -> TokenSyscallBalance:
        """
        Calculate and return the token amounts needed for token creation syscalls.

        Returns:
            `TokenSyscallBalance` with the token data and the amounts
        """
        raise NotImplementedError

    @abstractmethod
    def mint(self, amount: int, *, fee_payment_token: TokenDescription) -> TokenSyscallBalance:
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
    def melt(self, amount: int, *, fee_payment_token: TokenDescription) -> TokenSyscallBalance:
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
    def get_syscall_update_token_records(
        self,
        syscall_balance: TokenSyscallBalance
    ) -> list[UpdateTokenBalanceRecord | CreateTokenRecord]:
        """
        Create syscall update records for the given token operation.

        This method transforms a TokenSyscallBalance into a list of index records
        that will be appended to the call record's index_updates for tracking token operations.

        Args:
            syscall_balance: The token balance operation containing operation type,
                           token amounts, and payment details.

        Returns:
            A list of syscall update records (main token + fee payment).
        """
        raise NotImplementedError

    @staticmethod
    def get_rules(
        token_uid: TokenUid,
        token_version: TokenVersion,
        settings: HathorSettings
    ) -> TokenSyscallBalanceRules:
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
                raise AssertionError(f"NATIVE token version is not supported for token {token_uid.hex()}")
            case _:
                assert_never(token_version)


class _DepositTokenRules(TokenSyscallBalanceRules):

    def create_token(
        self,
        *,
        token_uid: TokenUid,
        token_symbol: str,
        token_name: str,
        amount: int,
        fee_payment_token: TokenDescription
    ) -> TokenSyscallBalance:
        assert amount > 0
        self._validate_payment_token(fee_payment_token)
        htr_amount = -get_deposit_token_deposit_amount(self._settings, amount)

        return TokenSyscallBalance(
            type=TokenOperationType.CREATE,
            token_version=TokenVersion.DEPOSIT,
            token_name=token_name,
            token_symbol=token_symbol,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=TokenUid(fee_payment_token.token_id), amount=htr_amount)
        )

    def mint(self, amount: int, *, fee_payment_token: TokenDescription) -> TokenSyscallBalance:
        assert amount > 0
        self._validate_payment_token(fee_payment_token)
        htr_amount = -get_deposit_token_deposit_amount(self._settings, amount)

        return TokenSyscallBalance(
            type=TokenOperationType.MINT,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=TokenUid(fee_payment_token.token_id), amount=htr_amount)
        )

    def melt(self, amount: int, *, fee_payment_token: TokenDescription) -> TokenSyscallBalance:
        assert amount > 0
        self._validate_payment_token(fee_payment_token)
        htr_amount = +get_deposit_token_withdraw_amount(self._settings, amount)

        return TokenSyscallBalance(
            type=TokenOperationType.MELT,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=-amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=TokenUid(fee_payment_token.token_id), amount=htr_amount)
        )

    def get_syscall_update_token_records(
        self,
        operation: TokenSyscallBalance,
    ) -> list[UpdateTokenBalanceRecord | CreateTokenRecord]:
        match operation.type:
            case TokenOperationType.MINT | TokenOperationType.CREATE:
                assert operation.token.amount > 0 and operation.fee_payment.amount < 0
            case TokenOperationType.MELT:
                assert operation.token.amount < 0 and operation.fee_payment.amount > 0
            case _:
                assert_never(operation.type)

        return operation.to_syscall_records()

    def _validate_payment_token(self, token:  TokenDescription) -> bool:
        if token.token_id == TokenUid(HATHOR_TOKEN_UID):
            return True
        raise NCInvalidFeePaymentToken("Only HTR is allowed to be used with deposit based token syscalls")


class _FeeTokenRules(TokenSyscallBalanceRules):

    def _get_fee_amount(self, fee_payment_token: TokenUid) -> int:
        # For fee tokens, we only need to pay the transaction fee, not deposit HTR
        if fee_payment_token == TokenUid(HATHOR_TOKEN_UID):
            fee_amount = -self._settings.FEE_PER_OUTPUT
        else:
            fee_amount = -int(self._settings.FEE_PER_OUTPUT / self._settings.TOKEN_DEPOSIT_PERCENTAGE)

        assert fee_amount < 0
        return fee_amount

    def create_token(
        self,
        *,
        token_uid: TokenUid,
        token_symbol: str,
        token_name: str,
        amount: int,
        fee_payment_token: TokenDescription
    ) -> TokenSyscallBalance:
        assert amount > 0
        self._validate_payment_token(fee_payment_token)
        # For fee tokens, we only need to pay the transaction fee, not deposit HTR
        fee_amount = self._get_fee_amount(TokenUid(fee_payment_token.token_id))

        return TokenSyscallBalance(
            type=TokenOperationType.CREATE,
            token_version=TokenVersion.FEE,
            token_name=token_name,
            token_symbol=token_symbol,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=TokenUid(fee_payment_token.token_id), amount=fee_amount)
        )

    def mint(self, amount: int, *, fee_payment_token: TokenDescription) -> TokenSyscallBalance:
        assert amount > 0
        self._validate_payment_token(fee_payment_token)
        fee_amount = self._get_fee_amount(TokenUid(fee_payment_token.token_id))
        return TokenSyscallBalance(
            type=TokenOperationType.MINT,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=TokenUid(fee_payment_token.token_id), amount=fee_amount)
        )

    def melt(self, amount: int, *, fee_payment_token: TokenDescription) -> TokenSyscallBalance:
        assert amount > 0
        self._validate_payment_token(fee_payment_token)
        fee_amount = self._get_fee_amount(TokenUid(fee_payment_token.token_id))

        return TokenSyscallBalance(
            type=TokenOperationType.MELT,
            token=TokenSyscallBalanceEntry(token_uid=self.token_uid, amount=-amount),
            fee_payment=TokenSyscallBalanceEntry(token_uid=TokenUid(fee_payment_token.token_id), amount=fee_amount)
        )

    def get_syscall_update_token_records(
        self,
        operation: TokenSyscallBalance,
    ) -> list[UpdateTokenBalanceRecord | CreateTokenRecord]:
        assert operation.fee_payment.amount < 0

        match operation.type:
            case TokenOperationType.MINT | TokenOperationType.CREATE:
                assert operation.token.amount > 0
            case TokenOperationType.MELT:
                assert operation.token.amount < 0
            case _:
                assert_never(operation.type)

        return operation.to_syscall_records()

    def _validate_payment_token(self, token_info: TokenDescription) -> None:
        match token_info.token_version:
            case TokenVersion.FEE:
                raise NCInvalidFeePaymentToken("fee-based tokens aren't allowed for paying fees")
            case TokenVersion.DEPOSIT:
                pass
            case TokenVersion.NATIVE:
                pass
            case _:
                assert_never(token_info.token_version)
