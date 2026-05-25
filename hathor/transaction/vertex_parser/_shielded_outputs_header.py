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

"""Standalone deserialization for the shielded-outputs header.

The header class is imported from hathorlib (not mirrored in hathor-core); the
real deserialization path is this free function, called from `_headers.py`,
rather than the (outdated) `VertexBaseHeader.deserialize` classmethod.
"""

from __future__ import annotations

import struct

from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback
from hathorlib.transaction.shielded_tx_output import (
    MAX_SHIELDED_OUTPUTS,
    ShieldedOutput,
    deserialize_shielded_output,
)


def deserialize_shielded_outputs_header(
    buf: bytes,
    *,
    verbose: VerboseCallback = None,
) -> tuple[list[ShieldedOutput], bytes]:
    """Parse `header_id(1) | num_outputs(1) | outputs…` and return (outputs, leftover)."""
    from hathor.transaction.exceptions import InvalidShieldedOutputError

    try:
        offset = 0
        header_id = buf[offset:offset + 1]
        offset += 1
        if verbose:
            verbose('header_id', header_id)
        if header_id != VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value:
            raise InvalidShieldedOutputError(
                f'unexpected header id: expected {VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value!r}, '
                f'got {header_id!r}'
            )

        num_outputs = buf[offset]
        offset += 1
        if verbose:
            verbose('num_shielded_outputs', num_outputs)

        if num_outputs < 1:
            raise InvalidShieldedOutputError('shielded outputs header must contain at least 1 output')
        if num_outputs > MAX_SHIELDED_OUTPUTS:
            raise InvalidShieldedOutputError(
                f'too many shielded outputs: {num_outputs} exceeds maximum {MAX_SHIELDED_OUTPUTS}'
            )

        shielded_outputs: list[ShieldedOutput] = []
        remaining = buf[offset:]
        for _ in range(num_outputs):
            output, remaining = deserialize_shielded_output(remaining)
            shielded_outputs.append(output)
    except InvalidShieldedOutputError:
        raise
    except (IndexError, struct.error, ValueError) as e:
        raise InvalidShieldedOutputError(f'malformed shielded outputs header: {e}') from e

    return shielded_outputs, bytes(remaining)
