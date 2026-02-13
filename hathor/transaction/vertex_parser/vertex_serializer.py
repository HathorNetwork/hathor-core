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

"""Public API for vertex binary serialization.

All binary serialization is routed through this module. Vertex classes
are pure data containers and do not implement serialization methods.
For deserialization, see ``vertex_deserializer``.

Usage:
    from hathor.transaction.vertex_parser import vertex_serializer

    data = vertex_serializer.serialize(tx)
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from hathor.serialization import Serializer
from hathor.transaction.base_transaction import TxVersion
from hathor.transaction.util import int_to_bytes

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction, TxInput, TxOutput
    from hathor.transaction.transaction import Transaction


def serialize(vertex: BaseTransaction) -> bytes:
    """Serialize a vertex to bytes. Replaces vertex.get_struct() / bytes(vertex)."""
    serializer = Serializer.build_bytes_serializer()
    serialize_without_nonce(serializer, vertex)
    serialize_nonce(serializer, vertex)
    serialize_headers(serializer, vertex)
    return bytes(serializer.finalize())


def serialize_funds(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Serialize the funds part of a vertex into the given Serializer."""
    match _try_tx_version(vertex.version):
        case TxVersion.ON_CHAIN_BLUEPRINT:
            from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint
            from hathor.transaction.vertex_parser._on_chain_blueprint import serialize_ocb_extra_fields
            from hathor.transaction.vertex_parser._transaction import serialize_tx_funds
            assert isinstance(vertex, OnChainBlueprint)
            serialize_tx_funds(serializer, vertex)
            serialize_ocb_extra_fields(serializer, vertex, skip_signature=False)
        case TxVersion.TOKEN_CREATION_TRANSACTION:
            from hathor.transaction.token_creation_tx import TokenCreationTransaction
            from hathor.transaction.vertex_parser._token_creation import serialize_token_creation_funds
            assert isinstance(vertex, TokenCreationTransaction)
            serialize_token_creation_funds(serializer, vertex)
        case TxVersion.REGULAR_BLOCK | TxVersion.MERGE_MINED_BLOCK | TxVersion.POA_BLOCK:
            from hathor.transaction.block import Block
            from hathor.transaction.vertex_parser._block import serialize_block_funds
            assert isinstance(vertex, Block)
            serialize_block_funds(serializer, vertex)
        case TxVersion.REGULAR_TRANSACTION:
            from hathor.transaction.transaction import Transaction
            from hathor.transaction.vertex_parser._transaction import serialize_tx_funds
            assert isinstance(vertex, Transaction)
            serialize_tx_funds(serializer, vertex)
        case None:
            _write_funds_fallback(serializer, vertex)


def serialize_graph(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Serialize the graph part of a vertex into the given Serializer."""
    match _try_tx_version(vertex.version):
        case TxVersion.POA_BLOCK:
            from hathor.consensus import poa
            from hathor.transaction.poa.poa_block import PoaBlock
            from hathor.transaction.vertex_parser._block import serialize_poa_block_graph_fields
            assert isinstance(vertex, PoaBlock)
            assert len(vertex.signer_id) == poa.SIGNER_ID_LEN
            serialize_poa_block_graph_fields(serializer, vertex)
        case TxVersion.REGULAR_BLOCK | TxVersion.MERGE_MINED_BLOCK:
            from hathor.transaction.block import Block
            from hathor.transaction.vertex_parser._block import serialize_block_graph_fields
            assert isinstance(vertex, Block)
            serialize_block_graph_fields(serializer, vertex)
        case TxVersion.REGULAR_TRANSACTION | TxVersion.TOKEN_CREATION_TRANSACTION | TxVersion.ON_CHAIN_BLUEPRINT:
            from hathor.transaction.vertex_parser._common import serialize_graph_fields
            serialize_graph_fields(serializer, vertex)
        case None:
            _write_graph_fallback(serializer, vertex)


def serialize_nonce(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Serialize the nonce/PoW part of a vertex into the given Serializer."""
    match _try_tx_version(vertex.version):
        case TxVersion.MERGE_MINED_BLOCK:
            from hathor.transaction.merge_mined_block import MergeMinedBlock
            assert isinstance(vertex, MergeMinedBlock)
            if not vertex.aux_pow:
                from hathor.transaction.aux_pow import BitcoinAuxPow
                serializer.write_bytes(bytes(BitcoinAuxPow.dummy()))
            else:
                serializer.write_bytes(bytes(vertex.aux_pow))
        case _:
            assert vertex.SERIALIZATION_NONCE_SIZE is not None
            serializer.write_bytes(int_to_bytes(vertex.nonce, vertex.SERIALIZATION_NONCE_SIZE))


def serialize_headers(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Serialize the headers of a vertex into the given Serializer."""
    from hathor.transaction.vertex_parser._headers import serialize_header
    for h in vertex.headers:
        serialize_header(serializer, h)


def serialize_without_nonce(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Serialize funds + graph (no nonce) into the given Serializer."""
    serialize_funds(serializer, vertex)
    serialize_graph(serializer, vertex)


def serialize_funds_bytes(vertex: BaseTransaction) -> bytes:
    """Serialize just the funds part of a vertex. Replaces vertex.get_funds_struct()."""
    serializer = Serializer.build_bytes_serializer()
    serialize_funds(serializer, vertex)
    return bytes(serializer.finalize())


def serialize_graph_bytes(vertex: BaseTransaction) -> bytes:
    """Serialize just the graph part of a vertex. Replaces vertex.get_graph_struct()."""
    serializer = Serializer.build_bytes_serializer()
    serialize_graph(serializer, vertex)
    return bytes(serializer.finalize())


def serialize_nonce_bytes(vertex: BaseTransaction) -> bytes:
    """Serialize just the nonce part of a vertex. Replaces vertex.get_struct_nonce()."""
    serializer = Serializer.build_bytes_serializer()
    serialize_nonce(serializer, vertex)
    return bytes(serializer.finalize())


def serialize_headers_bytes(vertex: BaseTransaction) -> bytes:
    """Serialize just the headers of a vertex. Replaces vertex.get_headers_struct()."""
    serializer = Serializer.build_bytes_serializer()
    serialize_headers(serializer, vertex)
    return bytes(serializer.finalize())


def serialize_without_nonce_bytes(vertex: BaseTransaction) -> bytes:
    """Serialize funds + graph (no nonce). Replaces vertex.get_struct_without_nonce()."""
    serializer = Serializer.build_bytes_serializer()
    serialize_without_nonce(serializer, vertex)
    return bytes(serializer.finalize())


def serialize_block_base_graph(block: BaseTransaction) -> bytes:
    """Serialize Block-level graph fields (without PoA extras). Used by PoA signing."""
    from hathor.transaction.block import Block
    from hathor.transaction.vertex_parser._block import serialize_block_graph_fields

    assert isinstance(block, Block)
    serializer = Serializer.build_bytes_serializer()
    serialize_block_graph_fields(serializer, block)
    return bytes(serializer.finalize())


def serialize_sighash(tx: Transaction, *, skip_cache: bool = False) -> bytes:
    """Serialize the sighash for a transaction. Replaces tx.get_sighash_all()."""
    if not skip_cache and tx._sighash_cache:
        return tx._sighash_cache

    from hathor.transaction.vertex_parser._headers import get_header_sighash_bytes
    headers_sighash = [get_header_sighash_bytes(h) for h in tx.headers]

    serializer = Serializer.build_bytes_serializer()

    match _try_tx_version(tx.version):
        case TxVersion.ON_CHAIN_BLUEPRINT:
            from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint
            from hathor.transaction.vertex_parser._on_chain_blueprint import serialize_ocb_extra_fields_bytes
            from hathor.transaction.vertex_parser._transaction import serialize_tx_sighash
            assert isinstance(tx, OnChainBlueprint)
            serialize_tx_sighash(serializer, tx, headers_sighash=headers_sighash)
            ret = bytes(serializer.finalize())
            ret += serialize_ocb_extra_fields_bytes(tx, skip_signature=True)
        case TxVersion.TOKEN_CREATION_TRANSACTION:
            from hathor.transaction.token_creation_tx import TokenCreationTransaction
            from hathor.transaction.vertex_parser._token_creation import serialize_token_creation_sighash
            assert isinstance(tx, TokenCreationTransaction)
            serialize_token_creation_sighash(serializer, tx, headers_sighash=headers_sighash)
            ret = bytes(serializer.finalize())
        case TxVersion.REGULAR_TRANSACTION:
            from hathor.transaction.vertex_parser._transaction import serialize_tx_sighash
            serialize_tx_sighash(serializer, tx, headers_sighash=headers_sighash)
            ret = bytes(serializer.finalize())
        case _:
            raise ValueError(f'Unknown tx version for sighash: {tx.version}')

    tx._sighash_cache = ret
    return ret


def get_sighash_data(tx: Transaction) -> bytes:
    """Return the sha256 hash of sighash_all. Replaces tx.get_sighash_all_data()."""
    if tx._sighash_data_cache is None:
        tx._sighash_data_cache = hashlib.sha256(serialize_sighash(tx)).digest()
    return tx._sighash_data_cache


def serialize_tx_input_bytes(txin: TxInput) -> bytes:
    """Serialize a TxInput. Replaces bytes(txin)."""
    from hathor.transaction.vertex_parser._common import serialize_tx_input as _ser
    serializer = Serializer.build_bytes_serializer()
    _ser(serializer, txin)
    return bytes(serializer.finalize())


def serialize_tx_input_sighash(txin: TxInput) -> bytes:
    """Serialize a TxInput for sighash (data cleared). Replaces txin.get_sighash_bytes()."""
    from hathor.transaction.vertex_parser._common import serialize_tx_input_sighash as _ser
    serializer = Serializer.build_bytes_serializer()
    _ser(serializer, txin)
    return bytes(serializer.finalize())


def serialize_tx_output_bytes(txout: TxOutput) -> bytes:
    """Serialize a TxOutput. Replaces bytes(txout)."""
    from hathor.transaction.vertex_parser._common import serialize_tx_output as _ser
    serializer = Serializer.build_bytes_serializer()
    _ser(serializer, txout)
    return bytes(serializer.finalize())


def serialize_token_info(tx: BaseTransaction) -> bytes:
    """Serialize token info for a TokenCreationTransaction. Replaces tx.serialize_token_info()."""
    from hathor.transaction.token_creation_tx import TokenCreationTransaction
    from hathor.transaction.vertex_parser._token_creation import _serialize_token_info
    assert isinstance(tx, TokenCreationTransaction)
    return _serialize_token_info(tx)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _try_tx_version(version: int) -> TxVersion | None:
    """Convert a version int to TxVersion, returning None for unknown versions."""
    try:
        return TxVersion(version)
    except (ValueError, AssertionError):
        return None


def _write_funds_fallback(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Fallback for unknown versions: use isinstance to pick the right serializer."""
    from hathor.transaction.block import Block
    from hathor.transaction.transaction import Transaction
    from hathor.transaction.vertex_parser._block import serialize_block_funds
    from hathor.transaction.vertex_parser._transaction import serialize_tx_funds

    if isinstance(vertex, Block):
        serialize_block_funds(serializer, vertex)
    else:
        assert isinstance(vertex, Transaction)
        serialize_tx_funds(serializer, vertex)


def _write_graph_fallback(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Fallback for unknown versions: use isinstance to pick the right serializer."""
    from hathor.transaction.block import Block
    from hathor.transaction.vertex_parser._block import serialize_block_graph_fields
    from hathor.transaction.vertex_parser._common import serialize_graph_fields

    if isinstance(vertex, Block):
        serialize_block_graph_fields(serializer, vertex)
    else:
        serialize_graph_fields(serializer, vertex)
