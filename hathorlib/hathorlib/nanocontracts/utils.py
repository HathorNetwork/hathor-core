# Copyright 2025 Hathor Labs
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

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from hathorlib.nanocontracts.types import (
    NC_METHOD_TYPE_ATTR,
    BlueprintId,
    ContractId,
    NCMethodType,
    TokenUid,
    VertexId,
)

CHILD_CONTRACT_ID_PREFIX: bytes = b'child-contract'
CHILD_TOKEN_ID_PREFIX: bytes = b'child-token'


def is_nc_public_method(method: Callable) -> bool:
    """Return True if the method is nc_public."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) == NCMethodType.PUBLIC


def is_nc_view_method(method: Callable) -> bool:
    """Return True if the method is nc_view."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) == NCMethodType.VIEW


def is_nc_fallback_method(method: Callable) -> bool:
    """Return True if the method is nc_fallback."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) == NCMethodType.FALLBACK


def derive_child_contract_id(parent_id: ContractId, salt: bytes, blueprint_id: BlueprintId) -> ContractId:
    """Derives the contract id for a nano contract created by another (parent) contract."""
    h = hashlib.sha256()
    h.update(CHILD_CONTRACT_ID_PREFIX)
    h.update(parent_id)
    h.update(salt)
    h.update(blueprint_id)
    return ContractId(VertexId(h.digest()))


def derive_child_token_id(parent_id: ContractId, token_symbol: str, *, salt: bytes = b'') -> TokenUid:
    """Derive the token id for a token created by a (parent) contract."""
    h = hashlib.sha256()
    h.update(CHILD_TOKEN_ID_PREFIX)
    h.update(parent_id)
    h.update(salt)
    h.update(token_symbol.encode('utf-8'))
    return TokenUid(VertexId(h.digest()))


def sha3(data: bytes) -> bytes:
    """Calculate the SHA3-256 of some data."""
    return hashlib.sha3_256(data).digest()


_verify_ecdsa_impl: Callable[[bytes, bytes, bytes], bool] | None = None


def set_verify_ecdsa_backend(impl: Callable[[bytes, bytes, bytes], bool]) -> None:
    """Set the backend implementation for verify_ecdsa."""
    global _verify_ecdsa_impl
    _verify_ecdsa_impl = impl


def verify_ecdsa(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify a cryptographic signature using a compressed public key for a SECP256K1 curve."""
    if _verify_ecdsa_impl is None:
        raise NotImplementedError('verify_ecdsa backend not set')
    return _verify_ecdsa_impl(public_key, data, signature)


def json_dumps(
    obj: object,
    *,
    ensure_ascii: bool = True,
    indent: int | str | None = None,
    separators: tuple[str, str] | None = (',', ':'),
    sort_keys: bool = False,
) -> str:
    """
    Serialize obj as a JSON. Arguments are a subset of Python's `json.dumps`.
    It automatically converts `bytes`-like values to their hex representation.
    """
    import json

    def dump_bytes(data: Any) -> str:
        if isinstance(data, bytes):
            return data.hex()
        raise TypeError(f'Object of type {type(data).__name__} is not JSON serializable')

    return json.dumps(
        obj,
        ensure_ascii=ensure_ascii,
        indent=indent,
        separators=separators,
        sort_keys=sort_keys,
        default=dump_bytes,
    )
