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

"""Standalone (de)serialization for the shielded-outputs header.

The header class is imported from hathorlib (not mirrored in hathor-core); the real
(de)serialization path is these free functions, driven through the serialization framework
from `_headers.py` — mirroring `_nano_header.py` / `_fee_header.py`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization.exceptions import SerializationError
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback, int_to_bytes
from hathorlib.transaction.shielded_tx_output import (
    MAX_SHIELDED_OUTPUTS,
    ShieldedOutput,
    deserialize_shielded_output,
    serialize_shielded_output,
)

if TYPE_CHECKING:
    from hathor.serialization import Deserializer, Serializer
    from hathor.transaction.headers import ShieldedOutputsHeader


def deserialize_shielded_outputs_header(
    deserializer: Deserializer,
    *,
    verbose: VerboseCallback = None,
) -> list[ShieldedOutput]:
    """Parse `header_id(1) | num_outputs(1) | outputs…` from the deserializer.

    Consumes exactly the header's bytes, leaving the deserializer positioned at the next header.
    """
    from hathor.transaction.exceptions import InvalidShieldedOutputError

    try:
        header_id = bytes(deserializer.read_bytes(1))
        if verbose:
            verbose('header_id', header_id)
        if header_id != VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value:
            raise InvalidShieldedOutputError(
                f'unexpected header id: expected {VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value!r}, '
                f'got {header_id!r}'
            )

        num_outputs = deserializer.read_byte()
        if verbose:
            verbose('num_shielded_outputs', num_outputs)
        if num_outputs < 1:
            raise InvalidShieldedOutputError('shielded outputs header must contain at least 1 output')
        if num_outputs > MAX_SHIELDED_OUTPUTS:
            raise InvalidShieldedOutputError(
                f'too many shielded outputs: {num_outputs} exceeds maximum {MAX_SHIELDED_OUTPUTS}'
            )

        shielded_outputs = [deserialize_shielded_output(deserializer) for _ in range(num_outputs)]
    except InvalidShieldedOutputError:
        raise
    except (SerializationError, ValueError) as e:
        raise InvalidShieldedOutputError(f'malformed shielded outputs header: {e}') from e

    return shielded_outputs


def serialize_shielded_outputs_header(
    serializer: Serializer,
    header: ShieldedOutputsHeader,
    *,
    skip_proofs: bool = False,
) -> None:
    """Serialize a ShieldedOutputsHeader into the serializer."""
    serializer.write_bytes(VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
    serializer.write_bytes(int_to_bytes(len(header.shielded_outputs), 1))
    for output in header.shielded_outputs:
        serialize_shielded_output(serializer, output, skip_proofs=skip_proofs)
