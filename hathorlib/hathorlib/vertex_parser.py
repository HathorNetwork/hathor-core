# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathorlib.headers import VertexBaseHeader, VertexHeaderId


class VertexParser:
    __slots__ = ()

    @staticmethod
    def get_supported_headers() -> dict[VertexHeaderId, type[VertexBaseHeader]]:
        """Return a dict of supported headers."""
        # NOTE: MintHeader/MeltHeader (0x14/0x15) imports and dict entries are
        # deferred — see hathorlib/headers/__init__.py for the full explanation.
        from hathorlib.headers import (
            FeeHeader,
            NanoHeader,
            ShieldedOutputsHeader,
            UnshieldBalanceHeader,
            VertexHeaderId,
        )
        return {
            VertexHeaderId.NANO_HEADER: NanoHeader,
            VertexHeaderId.FEE_HEADER: FeeHeader,
            VertexHeaderId.SHIELDED_OUTPUTS_HEADER: ShieldedOutputsHeader,
            VertexHeaderId.UNSHIELD_BALANCE_HEADER: UnshieldBalanceHeader,
        }

    @staticmethod
    def get_header_parser(header_id_bytes: bytes) -> type[VertexBaseHeader]:
        """Get the parser for a given header type."""
        from hathorlib.headers import VertexHeaderId
        header_id = VertexHeaderId(header_id_bytes)
        supported_headers = VertexParser.get_supported_headers()
        if header_id not in supported_headers:
            raise ValueError(f'Header type not supported: {header_id_bytes!r}')
        return supported_headers[header_id]
