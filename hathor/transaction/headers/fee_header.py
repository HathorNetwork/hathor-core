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

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.util import VerboseCallback, get_deposit_token_withdraw_amount
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
        from hathor.serialization import Deserializer
        from hathor.transaction.vertex_parser._fee_header import deserialize_fee_header
        deserializer = Deserializer.build_bytes_deserializer(buf)
        header = deserialize_fee_header(deserializer, tx, verbose=verbose)
        return header, bytes(deserializer.read_all())

    def serialize(self) -> bytes:
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser._fee_header import serialize_fee_header
        serializer = Serializer.build_bytes_serializer()
        serialize_fee_header(serializer, self)
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
