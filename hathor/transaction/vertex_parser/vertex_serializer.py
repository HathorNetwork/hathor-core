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

"""Public API for vertex binary serialization and deserialization.

All binary serialization is routed through this module. Vertex classes
are pure data containers and do not implement serialization methods.

Usage:
    from hathor.transaction.vertex_parser import vertex_serializer

    data = vertex_serializer.serialize(tx)
    tx = vertex_serializer.deserialize(data, storage=storage, settings=settings)
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from hathor.serialization import Serializer
from hathor.transaction.base_transaction import TxVersion
from hathor.transaction.util import VerboseCallback, int_to_bytes

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction, TxInput, TxOutput
    from hathor.transaction.token_info import TokenVersion
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
    match TxVersion(vertex.version):
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


def serialize_graph(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Serialize the graph part of a vertex into the given Serializer."""
    match TxVersion(vertex.version):
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


def serialize_nonce(serializer: Serializer, vertex: BaseTransaction) -> None:
    """Serialize the nonce/PoW part of a vertex into the given Serializer."""
    match TxVersion(vertex.version):
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

    match TxVersion(tx.version):
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
# Deserialization
# ---------------------------------------------------------------------------


def deserialize_tx_input(buf: bytes, *, verbose: VerboseCallback = None) -> tuple[TxInput, bytes]:
    """Deserialize a TxInput from bytes. Replaces TxInput.create_from_bytes()."""
    from hathor.serialization import Deserializer
    from hathor.transaction.vertex_parser._common import _deserialize_tx_input

    deserializer = Deserializer.build_bytes_deserializer(buf)
    txin = _deserialize_tx_input(deserializer, verbose=verbose)
    remaining = bytes(deserializer.read_all())
    return txin, remaining


def deserialize_tx_output(buf: bytes, *, verbose: VerboseCallback = None) -> tuple[TxOutput, bytes]:
    """Deserialize a TxOutput from bytes. Replaces TxOutput.create_from_bytes()."""
    from hathor.serialization import Deserializer
    from hathor.transaction.vertex_parser._common import _deserialize_tx_output

    deserializer = Deserializer.build_bytes_deserializer(buf)
    txout = _deserialize_tx_output(deserializer, verbose=verbose)
    remaining = bytes(deserializer.read_all())
    return txout, remaining


def deserialize_token_info(buf: bytes, *, verbose: VerboseCallback = None) -> tuple[str, str, TokenVersion, bytes]:
    """Deserialize token info from bytes. Replaces TokenCreationTransaction.deserialize_token_info()."""
    from hathor.transaction.token_info import TokenVersion
    from hathor.transaction.util import decode_string_utf8, unpack, unpack_len

    (raw_token_version,), buf = unpack('!B', buf)
    if verbose:
        verbose('token_version', raw_token_version)

    try:
        token_version = TokenVersion(raw_token_version)
    except ValueError:
        raise ValueError('unknown token version: {}'.format(raw_token_version))

    (name_len,), buf = unpack('!B', buf)
    if verbose:
        verbose('token_name_len', name_len)
    name, buf = unpack_len(name_len, buf)
    if verbose:
        verbose('token_name', name)
    (symbol_len,), buf = unpack('!B', buf)
    if verbose:
        verbose('token_symbol_len', symbol_len)
    symbol, buf = unpack_len(symbol_len, buf)
    if verbose:
        verbose('token_symbol', symbol)

    decoded_name = decode_string_utf8(name, 'Token name')
    decoded_symbol = decode_string_utf8(symbol, 'Token symbol')

    return decoded_name, decoded_symbol, token_version, buf
