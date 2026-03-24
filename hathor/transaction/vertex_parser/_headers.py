#  Copyright 2026 Hathor Labs
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

from typing import TYPE_CHECKING

from hathor.serialization import Serializer
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.vertex_parser._vertex_parser import VertexParser

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.serialization import Deserializer
    from hathor.transaction import BaseTransaction
    from hathor.transaction.headers import VertexBaseHeader


def deserialize_headers(
    deserializer: Deserializer,
    vertex: BaseTransaction,
    settings: HathorSettings,
) -> None:
    """Deserialize headers from the remaining bytes in the deserializer."""
    supported = VertexParser.get_supported_headers(settings)
    while not deserializer.is_empty():
        if len(vertex.headers) >= vertex.get_maximum_number_of_headers():
            raise ValueError('too many headers')
        header_type = bytes(deserializer.peek_bytes(1))
        header_id = VertexHeaderId(header_type)
        if header_id not in supported:
            raise ValueError(f'Header type not supported: {header_type!r}')
        header: VertexBaseHeader
        match header_id:
            case VertexHeaderId.NANO_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import NanoHeader
                from hathor.transaction.vertex_parser._nano_header import deserialize_nano_header
                assert isinstance(vertex, Transaction)
                data = deserialize_nano_header(deserializer)
                header = NanoHeader.create_from_data(vertex, data)
            case VertexHeaderId.FEE_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import FeeHeader
                from hathor.transaction.vertex_parser._fee_header import deserialize_fee_header
                assert isinstance(vertex, Transaction)
                fees = deserialize_fee_header(deserializer)
                header = FeeHeader(settings=settings, tx=vertex, fees=fees)
            case _:
                raise ValueError(f'Unknown header type: {header_type!r}')
        vertex.headers.append(header)


def serialize_header(serializer: Serializer, header: VertexBaseHeader) -> None:
    """Serialize a single header into the serializer."""
    from hathor.transaction.headers import FeeHeader, NanoHeader

    match header:
        case NanoHeader():
            from hathor.transaction.vertex_parser._nano_header import serialize_nano_header
            serialize_nano_header(serializer, header)
        case FeeHeader():
            from hathor.transaction.vertex_parser._fee_header import serialize_fee_header
            serialize_fee_header(serializer, header)
        case _:
            serializer.write_bytes(header.serialize())


def get_header_sighash_bytes(header: VertexBaseHeader) -> bytes:
    """Get sighash bytes for a header."""
    from hathor.transaction.headers import FeeHeader, NanoHeader

    match header:
        case NanoHeader():
            from hathor.transaction.vertex_parser._nano_header import serialize_nano_header
            serializer = Serializer.build_bytes_serializer()
            serialize_nano_header(serializer, header, skip_signature=True)
            return bytes(serializer.finalize())
        case FeeHeader():
            from hathor.transaction.vertex_parser._fee_header import serialize_fee_header
            serializer = Serializer.build_bytes_serializer()
            serialize_fee_header(serializer, header)
            return bytes(serializer.finalize())
        case _:
            return header.get_sighash_bytes()
