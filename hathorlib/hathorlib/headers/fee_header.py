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

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.headers.types import VertexHeaderId
from hathorlib.utils import int_to_bytes, unpack

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction
    from hathorlib.transaction import Transaction


@dataclass(frozen=True)
class FeeHeaderEntry:
    token_index: int
    amount: int


@dataclass(frozen=True)
class FeeEntry:
    token_uid: bytes
    amount: int


@dataclass(frozen=True)
class FeeHeader(VertexBaseHeader):
    tx: Transaction
    fees: list[FeeHeaderEntry]

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[FeeHeader, bytes]:
        from hathorlib.base_transaction import bytes_to_output_value

        header_id, buf = buf[:1], buf[1:]
        assert header_id == VertexHeaderId.FEE_HEADER.value

        fees: list[FeeHeaderEntry] = []
        (fees_len,), buf = unpack('!B', buf)

        for _ in range(fees_len):
            (token_index,), buf = unpack('!B', buf)
            amount, buf = bytes_to_output_value(buf)
            fees.append(FeeHeaderEntry(
                token_index=token_index,
                amount=amount,
            ))
        from hathorlib.transaction import Transaction
        assert isinstance(tx, Transaction)
        return cls(
            tx=tx,
            fees=fees,
        ), bytes(buf)

    def serialize(self) -> bytes:
        from hathorlib.base_transaction import output_value_to_bytes

        ret = [
            VertexHeaderId.FEE_HEADER.value,
            int_to_bytes(len(self.fees), 1)
        ]

        for fee in self.fees:
            ret.append(int_to_bytes(fee.token_index, 1))
            ret.append(output_value_to_bytes(fee.amount))

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
