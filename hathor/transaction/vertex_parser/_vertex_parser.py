# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from struct import error as StructError
from typing import TYPE_CHECKING, Type

from hathor.serialization.exceptions import SerializationError
from hathor.transaction.base_transaction import get_cls_from_tx_version
from hathor.transaction.headers import (
    AnyVertexHeader,
    FeeHeader,
    MeltHeader,
    MintHeader,
    NanoHeader,
    ShieldedOutputsHeader,
    UnshieldBalanceHeader,
    VertexHeaderId,
)

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import BaseTransaction
    from hathor.transaction.storage import TransactionStorage


class VertexParser:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings

    @staticmethod
    def get_supported_headers(settings: HathorSettings) -> dict[VertexHeaderId, Type[AnyVertexHeader]]:
        """Return a dict of supported headers."""
        supported_headers: dict[VertexHeaderId, Type[AnyVertexHeader]] = {}
        if settings.ENABLE_NANO_CONTRACTS:
            supported_headers[VertexHeaderId.NANO_HEADER] = NanoHeader
        if settings.ENABLE_FEE_BASED_TOKENS:
            supported_headers[VertexHeaderId.FEE_HEADER] = FeeHeader
        if settings.ENABLE_SHIELDED_TRANSACTIONS:
            supported_headers[VertexHeaderId.SHIELDED_OUTPUTS_HEADER] = ShieldedOutputsHeader
            supported_headers[VertexHeaderId.UNSHIELD_BALANCE_HEADER] = UnshieldBalanceHeader
            supported_headers[VertexHeaderId.MINT_HEADER] = MintHeader
            supported_headers[VertexHeaderId.MELT_HEADER] = MeltHeader
        return supported_headers

    @staticmethod
    def get_header_parser(header_id_bytes: bytes, settings: HathorSettings) -> Type[AnyVertexHeader]:
        """Get the parser for a given header type."""
        header_id = VertexHeaderId(header_id_bytes)
        supported_headers = VertexParser.get_supported_headers(settings)
        if header_id not in supported_headers:
            raise ValueError(f'Header type not supported: {header_id_bytes!r}')
        return supported_headers[header_id]

    def deserialize(self, data: bytes, storage: TransactionStorage | None = None) -> BaseTransaction:
        """Creates the correct tx subclass from a sequence of bytes."""
        # version field takes up the second byte only
        from hathor.transaction import TxVersion
        version = data[1]
        try:
            tx_version = TxVersion(version)
            is_valid = self._settings.CONSENSUS_ALGORITHM.is_vertex_version_valid(
                tx_version,
                include_genesis=True,
                settings=self._settings,
            )

            if not is_valid:
                raise StructError(f"invalid vertex version: {tx_version}")

            cls = get_cls_from_tx_version(tx_version)
            return cls.create_from_struct(data, storage=storage)
        except (ValueError, SerializationError) as e:
            raise StructError('Invalid bytes to create transaction subclass.') from e
