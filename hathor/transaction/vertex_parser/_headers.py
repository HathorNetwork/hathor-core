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
from hathorlib.decimal_places import VertexDecimalVersion

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.serialization import Deserializer
    from hathor.transaction import BaseTransaction
    from hathor.transaction.headers import AnyVertexHeader


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
        header: AnyVertexHeader
        match header_id:
            case VertexHeaderId.NANO_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import NanoHeader
                from hathor.transaction.vertex_parser._nano_header import deserialize_nano_header
                assert isinstance(vertex, Transaction)
                data = deserialize_nano_header(deserializer, decimal_version=vertex.get_decimal_version())
                header = NanoHeader.create_from_data(vertex, data)
            case VertexHeaderId.FEE_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import FeeHeader
                from hathor.transaction.vertex_parser._fee_header import deserialize_fee_header
                assert isinstance(vertex, Transaction)
                fees = deserialize_fee_header(deserializer, decimal_version=vertex.get_decimal_version())
                header = FeeHeader(settings=settings, tx=vertex, fees=fees)
            case VertexHeaderId.SHIELDED_OUTPUTS_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import ShieldedOutputsHeader
                from hathor.transaction.vertex_parser._shielded_outputs_header import (
                    deserialize_shielded_outputs_header,
                )
                assert isinstance(vertex, Transaction)
                # Deserialization goes through the standalone free function (framework-based),
                # not the header class's (outdated) deserialize classmethod. It consumes exactly
                # the header's bytes from the deserializer, like the Nano/Fee cases above.
                shielded_outputs = deserialize_shielded_outputs_header(deserializer)
                header = ShieldedOutputsHeader(shielded_outputs=shielded_outputs)
            case VertexHeaderId.UNSHIELD_BALANCE_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import UnshieldBalanceHeader
                from hathor.transaction.vertex_parser._unshield_balance_header import (
                    deserialize_unshield_balance_header,
                )
                assert isinstance(vertex, Transaction)
                excess_bf = deserialize_unshield_balance_header(deserializer)
                header = UnshieldBalanceHeader(excess_blinding_factor=excess_bf)
            case VertexHeaderId.MINT_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import MintHeader
                from hathor.transaction.vertex_parser._mint_melt_header import deserialize_mint_header
                assert isinstance(vertex, Transaction)
                mint_entries = deserialize_mint_header(deserializer)
                header = MintHeader(entries=mint_entries)
            case VertexHeaderId.MELT_HEADER:
                from hathor.transaction import Transaction
                from hathor.transaction.headers import MeltHeader
                from hathor.transaction.vertex_parser._mint_melt_header import deserialize_melt_header
                assert isinstance(vertex, Transaction)
                melt_entries = deserialize_melt_header(deserializer)
                header = MeltHeader(entries=melt_entries)
            case _:
                raise ValueError(f'Unknown header type: {header_type!r}')
        vertex.headers.append(header)


def serialize_header(
    serializer: Serializer,
    header: AnyVertexHeader,
    *,
    decimal_version: VertexDecimalVersion,
) -> None:
    """Serialize a single header into the serializer."""
    from hathor.transaction.headers import (
        FeeHeader,
        MeltHeader,
        MintHeader,
        NanoHeader,
        ShieldedOutputsHeader,
        UnshieldBalanceHeader,
    )

    match header:
        case NanoHeader():
            from hathor.transaction.vertex_parser._nano_header import serialize_nano_header
            serialize_nano_header(serializer, header, decimal_version=decimal_version)
        case FeeHeader():
            from hathor.transaction.vertex_parser._fee_header import serialize_fee_header
            serialize_fee_header(serializer, header, decimal_version=decimal_version)
        case ShieldedOutputsHeader():
            from hathor.transaction.vertex_parser._shielded_outputs_header import (
                serialize_shielded_outputs_header,
            )
            serialize_shielded_outputs_header(serializer, header)
        case UnshieldBalanceHeader():
            from hathor.transaction.vertex_parser._unshield_balance_header import (
                serialize_unshield_balance_header,
            )
            serialize_unshield_balance_header(serializer, header)
        case MintHeader():
            from hathor.transaction.vertex_parser._mint_melt_header import serialize_mint_header
            serialize_mint_header(serializer, header)
        case MeltHeader():
            from hathor.transaction.vertex_parser._mint_melt_header import serialize_melt_header
            serialize_melt_header(serializer, header)
        case _:
            raise AssertionError('unreachable')


def get_header_sighash_bytes(header: AnyVertexHeader, *, decimal_version: VertexDecimalVersion) -> bytes:
    """Get sighash bytes for a header."""
    from hathor.transaction.headers import (
        FeeHeader,
        MeltHeader,
        MintHeader,
        NanoHeader,
        ShieldedOutputsHeader,
        UnshieldBalanceHeader,
    )

    match header:
        case NanoHeader():
            from hathor.transaction.vertex_parser._nano_header import serialize_nano_header
            serializer = Serializer.build_bytes_serializer()
            serialize_nano_header(serializer, header, skip_signature=True, decimal_version=decimal_version)
            return bytes(serializer.finalize())
        case FeeHeader():
            from hathor.transaction.vertex_parser._fee_header import serialize_fee_header
            serializer = Serializer.build_bytes_serializer()
            serialize_fee_header(serializer, header, decimal_version=decimal_version)
            return bytes(serializer.finalize())
        case ShieldedOutputsHeader() | UnshieldBalanceHeader():
            # These headers own their sighash serialization (their full
            # serialization is bound to the signature). Mirrors the pre-existing
            # behavior before the explicit-arm refactor replaced the generic
            # `header.get_sighash_bytes()` fallback with the unreachable guard.
            return header.get_sighash_bytes()
        case MintHeader():
            from hathor.transaction.vertex_parser._mint_melt_header import serialize_mint_header
            serializer = Serializer.build_bytes_serializer()
            serialize_mint_header(serializer, header)
            return bytes(serializer.finalize())
        case MeltHeader():
            from hathor.transaction.vertex_parser._mint_melt_header import serialize_melt_header
            serializer = Serializer.build_bytes_serializer()
            serialize_melt_header(serializer, header)
            return bytes(serializer.finalize())
        case _:
            raise AssertionError('unreachable')
