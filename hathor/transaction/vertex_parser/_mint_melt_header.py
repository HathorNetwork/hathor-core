# Copyright 2026 Hathor Labs
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

"""Standalone (de)serialization for the mint and melt headers.

The header classes are imported from hathorlib (not mirrored in hathor-core); the real
(de)serialization path is these free functions, driven through the serialization framework
from `_headers.py` — mirroring `_shielded_outputs_header.py` / `_unshield_balance_header.py`.

The wire-format entry parsing (per-entry bounds, uniqueness) is owned by
``hathorlib.headers.mint_melt_header.deserialize_entries``; these functions only wrap it
with the framework's deserializer-driven byte consumption.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization.exceptions import SerializationError
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback, int_to_bytes
from hathorlib.headers.mint_melt_header import (
    ENTRY_SIZE,
    MAX_MINT_MELT_ENTRIES,
    MintMeltEntry,
    deserialize_entries,
)

if TYPE_CHECKING:
    from hathor.serialization import Deserializer


def _deserialize_mint_melt_header(
    deserializer: Deserializer,
    *,
    header_id_value: bytes,
    header_name: str,
    verbose: VerboseCallback = None,
) -> list[MintMeltEntry]:
    """Parse `header_id(1) | num_entries(1) | entries…` from the deserializer.

    Consumes exactly the header's bytes, leaving the deserializer positioned at the next header.
    """
    from hathor.transaction.exceptions import InvalidMintMeltHeaderError

    try:
        header_id = bytes(deserializer.read_bytes(1))
        if verbose:
            verbose('header_id', header_id)
        if header_id != header_id_value:
            raise InvalidMintMeltHeaderError(
                f'{header_name}: unexpected header id: expected {header_id_value!r}, got {header_id!r}'
            )

        num_entries = deserializer.read_byte()
        if verbose:
            verbose('num_entries', num_entries)
        if num_entries < 1:
            raise InvalidMintMeltHeaderError(f'{header_name}: must contain at least 1 entry')
        if num_entries > MAX_MINT_MELT_ENTRIES:
            raise InvalidMintMeltHeaderError(
                f'{header_name}: too many entries: {num_entries} exceeds maximum {MAX_MINT_MELT_ENTRIES}'
            )

        entries_buf = bytes(deserializer.read_bytes(num_entries * ENTRY_SIZE))
        # hathorlib.deserialize_entries owns the per-entry bound/uniqueness checks; it expects
        # the count byte to lead the buffer, so prepend it back.
        entries, leftover = deserialize_entries(
            int_to_bytes(num_entries, 1) + entries_buf, header_name=header_name
        )
        assert not leftover, f'{header_name}: unexpected leftover after entries'
    except InvalidMintMeltHeaderError:
        raise
    except (SerializationError, ValueError) as e:
        raise InvalidMintMeltHeaderError(f'malformed {header_name}: {e}') from e

    return entries


def deserialize_mint_header(
    deserializer: Deserializer,
    *,
    verbose: VerboseCallback = None,
) -> list[MintMeltEntry]:
    """Parse a MintHeader's entries from the deserializer."""
    return _deserialize_mint_melt_header(
        deserializer,
        header_id_value=VertexHeaderId.MINT_HEADER.value,
        header_name='MintHeader',
        verbose=verbose,
    )


def deserialize_melt_header(
    deserializer: Deserializer,
    *,
    verbose: VerboseCallback = None,
) -> list[MintMeltEntry]:
    """Parse a MeltHeader's entries from the deserializer."""
    return _deserialize_mint_melt_header(
        deserializer,
        header_id_value=VertexHeaderId.MELT_HEADER.value,
        header_name='MeltHeader',
        verbose=verbose,
    )
