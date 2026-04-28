# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Standalone (de)serialization for the unshield-balance header.

The header class is imported from hathorlib (not mirrored in hathor-core); the real
(de)serialization path is these free functions, driven through the serialization framework
from `_headers.py` — mirroring `_nano_header.py` / `_fee_header.py`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization.exceptions import SerializationError
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback
from hathorlib.headers.unshield_balance_header import EXCESS_BLINDING_FACTOR_SIZE

if TYPE_CHECKING:
    from hathor.serialization import Deserializer, Serializer
    from hathor.transaction.headers import UnshieldBalanceHeader


def deserialize_unshield_balance_header(
    deserializer: Deserializer,
    *,
    verbose: VerboseCallback = None,
) -> bytes:
    """Parse `header_id(1) | excess_blinding_factor(32)` from the deserializer; return the excess."""
    from hathor.transaction.exceptions import InvalidShieldedOutputError

    try:
        header_id = bytes(deserializer.read_bytes(1))
        if verbose:
            verbose('header_id', header_id)
        if header_id != VertexHeaderId.UNSHIELD_BALANCE_HEADER.value:
            raise InvalidShieldedOutputError(
                f'unexpected header id: expected '
                f'{VertexHeaderId.UNSHIELD_BALANCE_HEADER.value!r}, got {header_id!r}'
            )

        excess_bf = bytes(deserializer.read_bytes(EXCESS_BLINDING_FACTOR_SIZE))
        if verbose:
            verbose('excess_blinding_factor', excess_bf)
    except InvalidShieldedOutputError:
        raise
    except (SerializationError, ValueError) as e:
        raise InvalidShieldedOutputError(f'malformed unshield balance header: {e}') from e

    return excess_bf


def serialize_unshield_balance_header(serializer: Serializer, header: UnshieldBalanceHeader) -> None:
    """Serialize an UnshieldBalanceHeader into the serializer."""
    serializer.write_bytes(VertexHeaderId.UNSHIELD_BALANCE_HEADER.value)
    serializer.write_bytes(header.excess_blinding_factor)
