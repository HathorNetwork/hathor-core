#  Copyright 2024 Hathor Labs
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

from struct import error as StructError
from typing import TYPE_CHECKING, Type

from hathor.transaction.headers import FeeHeader, NanoHeader, VertexBaseHeader, VertexHeaderId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction import BaseTransaction
    from hathor.transaction.storage import TransactionStorage


class VertexParser:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings

    @staticmethod
    def get_supported_headers(settings: HathorSettings) -> dict[VertexHeaderId, Type[VertexBaseHeader]]:
        """Return a dict of supported headers."""
        supported_headers: dict[VertexHeaderId, Type[VertexBaseHeader]] = {}
        if settings.ENABLE_NANO_CONTRACTS:
            supported_headers[VertexHeaderId.NANO_HEADER] = NanoHeader
            supported_headers[VertexHeaderId.FEE_HEADER] = FeeHeader
        return supported_headers

    @staticmethod
    def get_header_parser(header_id_bytes: bytes, settings: HathorSettings) -> Type[VertexBaseHeader]:
        """Get the parser for a given header type."""
        header_id = VertexHeaderId(header_id_bytes)
        supported_headers = VertexParser.get_supported_headers(settings)
        if header_id not in supported_headers:
            raise ValueError(f'Header type not supported: {header_id_bytes!r}')
        return supported_headers[header_id]

    def deserialize(self, data: bytes, storage: TransactionStorage | None = None) -> BaseTransaction:
        """ Creates the correct tx subclass from a sequence of bytes
        """
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
            cls = tx_version.get_cls()
            return cls.create_from_struct(data, storage=storage)
        except ValueError as e:
            raise StructError('Invalid bytes to create transaction subclass.') from e
