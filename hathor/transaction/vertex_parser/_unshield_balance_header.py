# Copyright 2024 Hathor Labs
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

"""Standalone deserialization for the unshield-balance header.

The header class is imported from hathorlib (not mirrored in hathor-core); the
real deserialization path is this free function, called from `_headers.py`,
rather than the (outdated) `VertexBaseHeader.deserialize` classmethod.
"""

from __future__ import annotations

from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback
from hathorlib.headers.unshield_balance_header import EXCESS_BLINDING_FACTOR_SIZE


def deserialize_unshield_balance_header(
    buf: bytes,
    *,
    verbose: VerboseCallback = None,
) -> tuple[bytes, bytes]:
    """Parse `header_id(1) | excess_blinding_factor(32)` and return (excess_bf, leftover)."""
    from hathor.transaction.exceptions import InvalidShieldedOutputError

    header_size = 1 + EXCESS_BLINDING_FACTOR_SIZE
    if len(buf) < header_size:
        raise InvalidShieldedOutputError(
            f'unshield balance header requires {header_size} bytes, got {len(buf)}'
        )

    header_id = buf[0:1]
    if verbose:
        verbose('header_id', header_id)
    if header_id != VertexHeaderId.UNSHIELD_BALANCE_HEADER.value:
        raise InvalidShieldedOutputError(
            f'unexpected header id: expected '
            f'{VertexHeaderId.UNSHIELD_BALANCE_HEADER.value!r}, got {header_id!r}'
        )

    excess_bf = bytes(buf[1:1 + EXCESS_BLINDING_FACTOR_SIZE])
    if verbose:
        verbose('excess_blinding_factor', excess_bf)

    leftover = bytes(buf[header_size:])
    return excess_bf, leftover
