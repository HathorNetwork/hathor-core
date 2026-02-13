#  Copyright 2025 Hathor Labs
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

"""Serialization/deserialization for NanoHeader."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.leb128 import decode_leb128, encode_leb128
from hathor.serialization.encoding.output_value import decode_output_value, encode_output_value
from hathor.transaction.headers.nano_header import (
    ADDRESS_LEN_BYTES,
    ADDRESS_SEQNUM_SIZE,
    NanoHeader,
    NanoHeaderAction,
    _NC_SCRIPT_LEN_MAX_BYTES,
)
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback, int_to_bytes

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_nano_header(
    deserializer: Deserializer,
    tx: BaseTransaction,
    *,
    verbose: VerboseCallback = None,
) -> NanoHeader:
    """Deserialize a NanoHeader from the deserializer."""
    from hathor.transaction import Transaction
    assert isinstance(tx, Transaction)

    header_id = bytes(deserializer.read_bytes(1))
    if verbose:
        verbose('header_id', header_id)
    assert header_id == VertexHeaderId.NANO_HEADER.value

    nc_id = bytes(deserializer.read_bytes(32))
    if verbose:
        verbose('nc_id', nc_id)

    nc_seqnum = decode_leb128(deserializer.with_optional_max_bytes(ADDRESS_SEQNUM_SIZE), signed=False)
    if verbose:
        verbose('nc_seqnum', nc_seqnum)

    nc_method_len = deserializer.read_byte()
    if verbose:
        verbose('nc_method_len', nc_method_len)

    nc_method = bytes(deserializer.read_bytes(nc_method_len))
    if verbose:
        verbose('nc_method', nc_method)

    (nc_args_bytes_len,) = deserializer.read_struct('!H')
    if verbose:
        verbose('nc_args_bytes_len', nc_args_bytes_len)

    nc_args_bytes = bytes(deserializer.read_bytes(nc_args_bytes_len))
    if verbose:
        verbose('nc_args_bytes', nc_args_bytes)

    nc_actions: list[NanoHeaderAction] = []
    nc_actions_len = deserializer.read_byte()
    if verbose:
        verbose('nc_actions_len', nc_actions_len)
    for _ in range(nc_actions_len):
        action = _deserialize_nano_action(deserializer)
        nc_actions.append(action)

    nc_address = bytes(deserializer.read_bytes(ADDRESS_LEN_BYTES))
    if verbose:
        verbose('nc_address', nc_address)

    nc_script_len = decode_leb128(deserializer.with_optional_max_bytes(_NC_SCRIPT_LEN_MAX_BYTES), signed=False)
    if verbose:
        verbose('nc_script_len', nc_script_len)

    nc_script = bytes(deserializer.read_bytes(nc_script_len))
    if verbose:
        verbose('nc_script', nc_script)

    decoded_nc_method = nc_method.decode('ascii')

    return NanoHeader(
        tx=tx,
        nc_seqnum=nc_seqnum,
        nc_id=nc_id,
        nc_method=decoded_nc_method,
        nc_args_bytes=nc_args_bytes,
        nc_actions=nc_actions,
        nc_address=nc_address,
        nc_script=nc_script,
    )


def _deserialize_nano_action(deserializer: Deserializer) -> NanoHeaderAction:
    """Deserialize a single NanoHeaderAction from the deserializer."""
    from hathor.nanocontracts.types import NCActionType

    type_bytes = bytes(deserializer.read_bytes(1))
    action_type = NCActionType.from_bytes(type_bytes)
    token_index = deserializer.read_byte()
    amount = decode_output_value(deserializer)
    return NanoHeaderAction(
        type=action_type,
        token_index=token_index,
        amount=amount,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_nano_header(serializer: Serializer, header: NanoHeader, *, skip_signature: bool = False) -> None:
    """Serialize a NanoHeader into the serializer."""
    encoded_method = header.nc_method.encode('ascii')

    serializer.write_bytes(VertexHeaderId.NANO_HEADER.value)
    serializer.write_bytes(header.nc_id)
    encode_leb128(serializer.with_optional_max_bytes(ADDRESS_SEQNUM_SIZE), header.nc_seqnum, signed=False)
    serializer.write_bytes(int_to_bytes(len(encoded_method), 1))
    serializer.write_bytes(encoded_method)
    serializer.write_bytes(int_to_bytes(len(header.nc_args_bytes), 2))
    serializer.write_bytes(header.nc_args_bytes)

    serializer.write_bytes(int_to_bytes(len(header.nc_actions), 1))
    for action in header.nc_actions:
        _serialize_nano_action(serializer, action)

    serializer.write_bytes(header.nc_address)
    if not skip_signature:
        encode_leb128(
            serializer.with_optional_max_bytes(_NC_SCRIPT_LEN_MAX_BYTES),
            len(header.nc_script), signed=False,
        )
        serializer.write_bytes(header.nc_script)
    else:
        encode_leb128(
            serializer.with_optional_max_bytes(_NC_SCRIPT_LEN_MAX_BYTES),
            0, signed=False,
        )


def _serialize_nano_action(serializer: Serializer, action: NanoHeaderAction) -> None:
    """Serialize a single NanoHeaderAction into the serializer."""
    serializer.write_bytes(action.type.to_bytes())
    serializer.write_bytes(int_to_bytes(action.token_index, 1))
    encode_output_value(serializer, action.amount)
