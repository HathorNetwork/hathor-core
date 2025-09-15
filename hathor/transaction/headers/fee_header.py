# Copyright 2023 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from hathor.transaction.exceptions import FeeHeaderInvalidAmount
from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import (
    VerboseCallback,
    bytes_to_output_value,
    get_deposit_token_withdraw_amount,
    int_to_bytes,
    output_value_to_bytes,
    unpack,
)
from hathor.types import TokenUid

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.transaction import Transaction


@dataclass(slots=True, kw_only=True, frozen=True)
class FeeHeaderEntry:
    token_index: int
    amount: int


@dataclass(slots=True, kw_only=True, frozen=True)
class FeeEntry:
    token_uid: TokenUid
    amount: int

    def __post_init__(self) -> None:
        """Validate the amount."""
        from hathor.conf.settings import HATHOR_TOKEN_UID

        if self.amount <= 0:
            raise FeeHeaderInvalidAmount(f'fees should be a positive integer, got {self.amount}')

        if self.token_uid != HATHOR_TOKEN_UID and self.amount % 100 != 0:
            raise FeeHeaderInvalidAmount(f'fees using deposit custom tokens should be a multiple of 100,'
                                         f' got {self.amount}')


@dataclass(slots=True, kw_only=True)
class FeeHeader(VertexBaseHeader):
    tx: 'Transaction'
    fees: list[FeeHeaderEntry]
    _settings: HathorSettings

    def __init__(self, settings: HathorSettings, tx: 'Transaction', fees: list[FeeHeaderEntry]):
        self.tx = tx
        self.fees = fees
        self._settings = settings

    @classmethod
    def _deserialize_fee(cls, buf: bytes) -> tuple[FeeHeaderEntry, bytes]:
        (token_index,), buf = unpack('!B', buf)
        amount, buf = bytes_to_output_value(buf)
        return FeeHeaderEntry(
            token_index=token_index,
            amount=amount,
        ), buf

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None
    ) -> tuple[FeeHeader, bytes]:
        buf = memoryview(buf)

        header_id, buf = buf[:1], buf[1:]
        if verbose:
            verbose('header_id', header_id)
        assert header_id == VertexHeaderId.FEE_HEADER.value

        fees: list[FeeHeaderEntry] = []
        (fees_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('fees_len', fees_len)
        for _ in range(fees_len):
            fee, buf = cls._deserialize_fee(buf)
            fees.append(fee)

        from hathor.transaction import Transaction
        assert isinstance(tx, Transaction)
        return cls(
            settings=tx._settings,
            tx=tx,
            fees=fees,
        ), bytes(buf)

    @classmethod
    def _serialize_fee(cls, fee: FeeHeaderEntry) -> bytes:
        ret = [
            int_to_bytes(fee.token_index, 1),
            output_value_to_bytes(fee.amount),
        ]
        return b''.join(ret)

    def serialize(self) -> bytes:
        ret: list[bytes] = [VertexHeaderId.FEE_HEADER.value, int_to_bytes(len(self.fees), 1)]

        for fee in self.fees:
            ret.append(self._serialize_fee(fee))

        return b''.join(ret)

    def get_sighash_bytes(self) -> bytes:
        return self.serialize()

    def get_fees(self) -> list[FeeEntry]:
        return [
            FeeEntry(
                token_uid=self.tx.get_token_uid(fee.token_index),
                amount=fee.amount
            )
            for fee in self.fees
        ]

    def total_fee_amount(self) -> int:
        """Sum fees amounts in this header and return as HTR"""
        total_fee = 0
        for fee in self.get_fees():
            if fee.token_uid == self._settings.HATHOR_TOKEN_UID:
                total_fee += fee.amount
            else:
                total_fee += get_deposit_token_withdraw_amount(self._settings, fee.amount)
        return total_fee
