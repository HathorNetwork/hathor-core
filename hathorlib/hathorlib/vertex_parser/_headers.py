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

"""Central per-class header (de)serialization dispatcher.

`BaseTransaction.get_headers_struct`, `BaseTransaction.get_header_from_bytes`,
and `Transaction.get_sighash_all_data` iterate over `self.headers`
polymorphically. Rather than having each header class own its own bytes-in /
bytes-out wrappers (and rather than letting the abstract base require them),
the four shielded headers hand off to the helpers in this package and are
dispatched by class here. FeeHeader and NanoHeader still implement the
wrapper methods directly; this module's fallback path delegates to them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathorlib.headers import (
    MeltHeader,
    MintHeader,
    ShieldedOutputsHeader,
    UnshieldBalanceHeader,
    VertexBaseHeader,
)
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.vertex_parser._mint_melt_header import (
    deserialize_melt_header,
    deserialize_mint_header,
    serialize_melt_header,
    serialize_mint_header,
)
from hathorlib.vertex_parser._shielded_outputs_header import (
    deserialize_shielded_outputs_header,
    serialize_shielded_outputs_header,
    serialize_shielded_outputs_header_sighash,
)
from hathorlib.vertex_parser._unshield_balance_header import (
    deserialize_unshield_balance_header,
    serialize_unshield_balance_header,
)

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction


def _transaction_classes() -> tuple[type, ...]:
    """Return the tuple of classes that count as a Transaction for header dispatch.

    Always includes hathorlib's `Transaction`. When hathor-core is also
    installed (the normal case from a hathor-core process), its parallel
    `hathor.transaction.Transaction` class is included too — it has the same
    duck-typed shape (carries headers, accepts header.tx back-refs) but is a
    different class identity.
    """
    from hathorlib.transaction import Transaction as _HLTx
    classes: tuple[type, ...] = (_HLTx,)
    try:
        from hathor.transaction import Transaction as _HCTx
    except ImportError:
        return classes
    return (_HLTx, _HCTx)


def serialize_header(serializer: Serializer, header: VertexBaseHeader) -> None:
    """Serialize one header into the given serializer.

    Dispatches by class for the four shielded headers; falls back to the
    header class's own bytes-returning `serialize()` (FeeHeader / NanoHeader)
    for everything else, writing the result to the serializer in one shot.
    """
    match header:
        case ShieldedOutputsHeader():
            serialize_shielded_outputs_header(serializer, header)
        case UnshieldBalanceHeader():
            serialize_unshield_balance_header(serializer, header)
        case MintHeader():
            serialize_mint_header(serializer, header)
        case MeltHeader():
            serialize_melt_header(serializer, header)
        case _:
            serializer.write_bytes(header.serialize())


def deserialize_header(
    deserializer: Deserializer,
    tx: BaseTransaction,
    header_class: type[VertexBaseHeader],
) -> VertexBaseHeader:
    """Deserialize one header from the given deserializer.

    Dispatches by class for the four shielded headers. For headers that still
    own their bytes-in/bytes-out wrappers (FeeHeader, NanoHeader) we drain
    the rest of the deserializer, hand it to the class, and push any
    leftover back so the outer loop can continue.
    """
    # Per-class dispatch for the four shielded headers. The runtime check
    # accepts either hathorlib's or hathor-core's `Transaction` class so
    # this dispatcher works whether it was reached from hathorlib's
    # `BaseTransaction.get_header_from_bytes` (hathorlib's `Transaction`)
    # or from hathor-core's `vertex_parser._headers` orchestrator
    # (hathor-core's `Transaction`). Both classes have the duck-typed
    # `headers` attribute the helpers ultimately need.
    if header_class is ShieldedOutputsHeader:
        assert isinstance(tx, _transaction_classes())
        return deserialize_shielded_outputs_header(deserializer, tx)  # type: ignore[arg-type]
    if header_class is UnshieldBalanceHeader:
        assert isinstance(tx, _transaction_classes())
        return deserialize_unshield_balance_header(deserializer, tx)  # type: ignore[arg-type]
    if header_class is MintHeader:
        assert isinstance(tx, _transaction_classes())
        return deserialize_mint_header(deserializer, tx)  # type: ignore[arg-type]
    if header_class is MeltHeader:
        assert isinstance(tx, _transaction_classes())
        return deserialize_melt_header(deserializer, tx)  # type: ignore[arg-type]
    # Fallback for headers still on the bytes-in/bytes-out style.
    remaining = bytes(deserializer.read_all())
    header, leftover = header_class.deserialize(tx, remaining)
    if leftover:
        deserializer.replace_remaining(leftover)
    return header


def serialize_sighash_bytes(serializer: Serializer, header: VertexBaseHeader) -> None:
    """Write a header's sighash subset into the given serializer.

    For the shielded headers we use their dedicated sighash serializer (which
    skips the proofs); for everything else we fall back to the class's own
    `get_sighash_bytes()`. UnshieldBalance / Mint / Melt sighash equals the
    full serialization, so we reuse the serializer there.
    """
    match header:
        case ShieldedOutputsHeader():
            serialize_shielded_outputs_header_sighash(serializer, header)
        case UnshieldBalanceHeader():
            serialize_unshield_balance_header(serializer, header)
        case MintHeader():
            serialize_mint_header(serializer, header)
        case MeltHeader():
            serialize_melt_header(serializer, header)
        case _:
            serializer.write_bytes(header.get_sighash_bytes())


def get_sighash_bytes(header: VertexBaseHeader) -> bytes:
    """Convenience wrapper: build a fresh serializer and return the sighash bytes."""
    serializer = Serializer.build_bytes_serializer()
    serialize_sighash_bytes(serializer, header)
    return bytes(serializer.finalize())


def header_to_bytes(header: VertexBaseHeader) -> bytes:
    """Convenience wrapper: build a fresh serializer and return the full wire bytes."""
    serializer = Serializer.build_bytes_serializer()
    serialize_header(serializer, header)
    return bytes(serializer.finalize())
