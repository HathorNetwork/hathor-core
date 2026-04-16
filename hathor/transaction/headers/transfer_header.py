# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from hathor.transaction.headers.nano_header import ADDRESS_SEQNUM_SIZE
from hathor.transaction.util import VerboseCallback
from hathor.types import Address, Amount, TxOutputScript

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.transaction import Transaction


@dataclass(slots=True, kw_only=True, frozen=True)
class InputAddress:
    address: Address
    seqnum: int
    script: TxOutputScript

    def __post_init__(self) -> None:
        assert self.seqnum >= 0
        assert self.seqnum.bit_length() <= ADDRESS_SEQNUM_SIZE * 8


@dataclass(slots=True, kw_only=True, frozen=True)
class TxTransferInput:
    address_index: int
    amount: Amount
    token_index: int


@dataclass(slots=True, kw_only=True, frozen=True)
class TxTransferOutput:
    address: Address
    amount: Amount
    token_index: int


@dataclass(slots=True, kw_only=True)
class TransferHeader:
    tx: Transaction

    addresses: list[InputAddress]
    inputs: list[TxTransferInput]
    outputs: list[TxTransferOutput]

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None
    ) -> tuple[TransferHeader, bytes]:
        from hathor.serialization import Deserializer
        from hathor.transaction import Transaction
        from hathor.transaction.vertex_parser._transfer_header import deserialize_transfer_header

        assert isinstance(tx, Transaction)

        deserializer = Deserializer.build_bytes_deserializer(buf)
        addresses, inputs, outputs = deserialize_transfer_header(
            deserializer,
            token_amount_version=tx.get_token_amount_version(),
            verbose=verbose,
        )
        header = cls(
            tx=tx,
            addresses=addresses,
            inputs=inputs,
            outputs=outputs,
        )
        return header, bytes(deserializer.read_all())

    def serialize(self) -> bytes:
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser._transfer_header import serialize_transfer_header

        serializer = Serializer.build_bytes_serializer()
        serialize_transfer_header(serializer, self, token_amount_version=self.tx.get_token_amount_version())
        return bytes(serializer.finalize())

    def get_sighash_bytes(self) -> bytes:
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser._transfer_header import serialize_transfer_header

        serializer = Serializer.build_bytes_serializer()
        serialize_transfer_header(
            serializer,
            self,
            skip_signature=True,
            token_amount_version=self.tx.get_token_amount_version(),
        )
        return bytes(serializer.finalize())
