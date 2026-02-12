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

"""Serialization/deserialization for OnChainBlueprint-specific fields."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer, Serializer
from hathor.transaction.util import VerboseCallback, int_to_bytes

if TYPE_CHECKING:
    from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint


def serialize_ocb_extra_fields(serializer: Serializer, tx: OnChainBlueprint, *, skip_signature: bool = False) -> None:
    """Serialize OCB-specific fields (code, nc_pubkey, nc_signature)."""
    serializer.write_bytes(tx.serialize_code())
    serializer.write_bytes(int_to_bytes(len(tx.nc_pubkey), 1))
    serializer.write_bytes(tx.nc_pubkey)
    if not skip_signature:
        serializer.write_bytes(int_to_bytes(len(tx.nc_signature), 1))
        serializer.write_bytes(tx.nc_signature)
    else:
        serializer.write_bytes(int_to_bytes(0, 1))


def serialize_ocb_extra_fields_bytes(tx: OnChainBlueprint, *, skip_signature: bool = False) -> bytes:
    """Serialize OCB-specific fields to bytes (used by sighash)."""
    serializer = Serializer.build_bytes_serializer()
    serialize_ocb_extra_fields(serializer, tx, skip_signature=skip_signature)
    return bytes(serializer.finalize())


def deserialize_ocb_extra_fields(
    deserializer: Deserializer, tx: OnChainBlueprint, *, verbose: VerboseCallback = None,
) -> None:
    """Deserialize OCB-specific fields (code, nc_pubkey, nc_signature) from a Deserializer."""
    from hathor.conf.get_settings import get_global_settings
    from hathor.nanocontracts.on_chain_blueprint import ON_CHAIN_BLUEPRINT_VERSION, Code

    settings = get_global_settings()

    # Code
    (ocb_version,) = deserializer.read_struct('!B')
    if verbose:
        verbose('ocb_version', ocb_version)
    if ocb_version != ON_CHAIN_BLUEPRINT_VERSION:
        raise ValueError(f'unknown on-chain blueprint version: {ocb_version}')

    (serialized_code_len,) = deserializer.read_struct('!L')
    if verbose:
        verbose('serialized_code_len', serialized_code_len)
    max_len = settings.NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_COMPRESSED
    if serialized_code_len > max_len:
        raise ValueError(f'compressed code data is too large: {serialized_code_len} > {max_len}')
    serialized_code = bytes(deserializer.read_bytes(serialized_code_len))
    if verbose:
        verbose('serialized_code', serialized_code)
    tx.code = Code.from_bytes(serialized_code, settings)

    # nc_pubkey
    (nc_pubkey_len,) = deserializer.read_struct('!B')
    if verbose:
        verbose('nc_pubkey_len', nc_pubkey_len)
    tx.nc_pubkey = bytes(deserializer.read_bytes(nc_pubkey_len))
    if verbose:
        verbose('nc_pubkey', tx.nc_pubkey)

    # nc_signature
    (nc_signature_len,) = deserializer.read_struct('!B')
    if verbose:
        verbose('nc_signature_len', nc_signature_len)
    tx.nc_signature = bytes(deserializer.read_bytes(nc_signature_len))
    if verbose:
        verbose('nc_signature', tx.nc_signature)
