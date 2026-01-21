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

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.output_value import decode_output_value
from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import (
    VerboseCallback,
    get_deposit_token_withdraw_amount,
    int_to_bytes,
    output_value_to_bytes,
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

    def to_json(self) -> dict:
        return {
            'token_uid': self.token_uid.hex(),
            'amount': self.amount,
        }


@dataclass(slots=True, kw_only=True)
class FeeHeader(VertexBaseHeader):
    # transaction that contains the fee header
    tx: 'Transaction'
    # list of tokens and amounts that will be used to pay fees in the transaction
    fees: list[FeeHeaderEntry]
    settings: HathorSettings

    def __init__(self, settings: HathorSettings, tx: 'Transaction', fees: list[FeeHeaderEntry]):
        self.tx = tx
        self.fees = fees
        self.settings = settings

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None
    ) -> tuple[FeeHeader, bytes]:
        deserializer = Deserializer.build_bytes_deserializer(buf)

        header_id = deserializer.read_bytes(1)
        if verbose:
            verbose('header_id', header_id)
        assert header_id == VertexHeaderId.FEE_HEADER.value

        fees: list[FeeHeaderEntry] = []
        fees_len = deserializer.read_byte()
        if verbose:
            verbose('fees_len', fees_len)
        for _ in range(fees_len):
            token_index = deserializer.read_byte()
            amount = decode_output_value(deserializer)
            fees.append(FeeHeaderEntry(
                token_index=token_index,
                amount=amount,
            ))

        from hathor.transaction import Transaction
        assert isinstance(tx, Transaction)
        remaining_bytes = bytes(deserializer.read_all())
        return cls(
            settings=tx._settings,
            tx=tx,
            fees=fees,
        ), remaining_bytes

    def serialize(self) -> bytes:
        serializer = Serializer.build_bytes_serializer()
        serializer.write_bytes(VertexHeaderId.FEE_HEADER.value)
        serializer.write_bytes(int_to_bytes(len(self.fees), 1))

        for fee in self.fees:
            serializer.write_bytes(int_to_bytes(fee.token_index, 1))
            serializer.write_bytes(output_value_to_bytes(fee.amount))

        return bytes(serializer.finalize())

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
            if fee.token_uid == self.settings.HATHOR_TOKEN_UID:
                total_fee += fee.amount
            else:
                total_fee += get_deposit_token_withdraw_amount(self.settings, fee.amount)
        return total_fee
