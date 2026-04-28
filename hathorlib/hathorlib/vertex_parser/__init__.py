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

from typing import TYPE_CHECKING

from hathorlib.conf.settings import FeatureSetting, HathorSettings as _HathorSettings

if TYPE_CHECKING:
    from hathorlib.headers import VertexBaseHeader, VertexHeaderId


class VertexParser:
    __slots__ = ()

    @staticmethod
    def get_supported_headers(
        settings: _HathorSettings | None = None,
    ) -> dict[VertexHeaderId, type[VertexBaseHeader]]:
        """Return a dict of supported headers.

        When ``settings`` is provided and ``ENABLE_SHIELDED_TRANSACTIONS`` is
        anything other than ``DISABLED``, the four shielded-related headers
        (ShieldedOutputs, UnshieldBalance, Mint, Melt) are also admitted.
        Passing ``None`` keeps backward compat: only the always-on Nano and
        Fee headers are returned.
        """
        from hathorlib.headers import (
            FeeHeader,
            MeltHeader,
            MintHeader,
            NanoHeader,
            ShieldedOutputsHeader,
            UnshieldBalanceHeader,
            VertexHeaderId,
        )
        supported: dict[VertexHeaderId, type[VertexBaseHeader]] = {
            VertexHeaderId.NANO_HEADER: NanoHeader,
            VertexHeaderId.FEE_HEADER: FeeHeader,
        }
        if settings is not None and settings.ENABLE_SHIELDED_TRANSACTIONS != FeatureSetting.DISABLED:
            supported[VertexHeaderId.SHIELDED_OUTPUTS_HEADER] = ShieldedOutputsHeader
            supported[VertexHeaderId.UNSHIELD_BALANCE_HEADER] = UnshieldBalanceHeader
            supported[VertexHeaderId.MINT_HEADER] = MintHeader
            supported[VertexHeaderId.MELT_HEADER] = MeltHeader
        return supported

    @staticmethod
    def get_header_parser(
        header_id_bytes: bytes,
        settings: _HathorSettings | None = None,
    ) -> type[VertexBaseHeader]:
        """Get the parser for a given header type."""
        from hathorlib.headers import VertexHeaderId
        header_id = VertexHeaderId(header_id_bytes)
        supported_headers = VertexParser.get_supported_headers(settings)
        if header_id not in supported_headers:
            raise ValueError(f'Header type not supported: {header_id_bytes!r}')
        return supported_headers[header_id]
