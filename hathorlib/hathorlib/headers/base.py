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

from abc import ABC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction


class VertexBaseHeader(ABC):
    """Marker base class for all vertex headers.

    The bytes-in/bytes-out methods (`serialize`, `deserialize`,
    `get_sighash_bytes`) have concrete defaults that route through the
    central dispatcher in ``hathorlib.vertex_parser._headers``. Subclasses
    that already implement bytes-level work directly (FeeHeader, NanoHeader)
    keep their overrides; subclasses whose wire format is owned by
    ``hathorlib.vertex_parser._<name>_header`` (the four shielded headers)
    don't override and rely on the dispatcher.
    """

    @classmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[VertexBaseHeader, bytes]:
        """Default: look up the right per-class deserializer in the dispatcher."""
        from hathorlib.serialization import Deserializer
        from hathorlib.vertex_parser._headers import deserialize_header
        deserializer = Deserializer.build_bytes_deserializer(buf)
        header = deserialize_header(deserializer, tx, cls)
        return header, bytes(deserializer.read_all())

    def serialize(self) -> bytes:
        """Default: route through the central dispatcher."""
        from hathorlib.vertex_parser._headers import header_to_bytes
        return header_to_bytes(self)

    def get_sighash_bytes(self) -> bytes:
        """Default: route through the central dispatcher."""
        from hathorlib.vertex_parser._headers import get_sighash_bytes
        return get_sighash_bytes(self)
