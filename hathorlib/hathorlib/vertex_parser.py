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

if TYPE_CHECKING:
    from hathorlib.headers import VertexBaseHeader, VertexHeaderId


class VertexParser:
    __slots__ = ()

    @staticmethod
    def get_supported_headers() -> dict[VertexHeaderId, type[VertexBaseHeader]]:
        """Return a dict of supported headers."""
        from hathorlib.headers import FeeHeader, NanoHeader, VertexHeaderId
        return {
            VertexHeaderId.NANO_HEADER: NanoHeader,
            VertexHeaderId.FEE_HEADER: FeeHeader,
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
