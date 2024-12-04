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
from hathor.transaction.static_metadata import VertexStaticMetadata
from hathor.utils import pickle
from hathor.utils.pickle import register_custom_pickler

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction
    from hathor.transaction.storage import TransactionStorage


class VertexParser:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings
        from hathor.transaction import Block, MergeMinedBlock, Transaction
        from hathor.transaction.base_transaction import GenericVertex
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        for vertex_type in [Block, MergeMinedBlock, Transaction, TokenCreationTransaction]:
            assert issubclass(vertex_type, GenericVertex)
            register_custom_pickler(
                vertex_type, serializer=self._custom_vertex_pickler, deserializer=self._custom_vertex_unpickler
            )

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
        except ValueError:
            raise StructError('Invalid bytes to create transaction subclass.')

    @staticmethod
    def _custom_vertex_pickler(vertex: BaseTransaction) -> bytes:
        data = vertex.get_struct(), vertex.static_metadata.json_dumpb() if vertex._static_metadata else None
        return pickle.dumps(data)

    def _custom_vertex_unpickler(self, data: bytes) -> BaseTransaction:
        vertex_bytes, static_metadata_bytes = pickle.loads(data)
        vertex = self.deserialize(vertex_bytes)
        if static_metadata_bytes is not None:
            static_metadata = VertexStaticMetadata.from_bytes(static_metadata_bytes, target=vertex)
            vertex.set_static_metadata(static_metadata)
        return vertex
