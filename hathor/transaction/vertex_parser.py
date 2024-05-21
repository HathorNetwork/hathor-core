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
from typing import TYPE_CHECKING

from hathor.conf.settings import HathorSettings

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction
    from hathor.transaction.storage import TransactionStorage


class VertexParser:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings

    def deserialize(self, data: bytes, storage: TransactionStorage | None = None) -> BaseTransaction:
        """ Creates the correct tx subclass from a sequence of bytes
        """
        # version field takes up the second byte only
        from hathor.transaction import TxVersion
        version = data[1]
        try:
            tx_version = TxVersion(version)
            if not self._settings.CONSENSUS_ALGORITHM.is_vertex_version_valid(tx_version, include_genesis=True):
                raise StructError(f"invalid vertex version: {tx_version}")
            cls = tx_version.get_cls()
            return cls.create_from_struct(data, storage=storage)
        except ValueError as e:
            raise StructError('Invalid bytes to create transaction subclass.') from e
