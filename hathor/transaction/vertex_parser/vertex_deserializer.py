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

"""Public API for vertex binary deserialization.

Usage:
    from hathor.transaction.vertex_parser import vertex_deserializer

    tx = vertex_deserializer.deserialize(data, storage=storage, settings=settings)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.serialization import Deserializer
from hathor.transaction.base_transaction import TxVersion
from hathor.transaction.util import VerboseCallback

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction.base_transaction import BaseTransaction, TxInput, TxOutput
    from hathor.transaction.block import Block
    from hathor.transaction.merge_mined_block import MergeMinedBlock
    from hathor.transaction.storage import TransactionStorage
    from hathor.transaction.token_creation_tx import TokenCreationTransaction
    from hathor.transaction.token_info import TokenVersion
    from hathor.transaction.transaction import Transaction


def deserialize(
    data: bytes,
    storage: TransactionStorage | None = None,
    *,
    settings: HathorSettings | None = None,
    verbose: VerboseCallback = None,
) -> BaseTransaction:
    """Deserialize a vertex from bytes. Dispatches by TxVersion.

    This is the single entry point for deserializing any vertex type.
    """
    from hathor.conf.get_settings import get_global_settings

    if settings is None:
        settings = get_global_settings()

    version = _try_tx_version(data[1])

    match version:
        case TxVersion.REGULAR_TRANSACTION:
            vertex: BaseTransaction = deserialize_transaction(data, settings, verbose)
        case TxVersion.TOKEN_CREATION_TRANSACTION:
            vertex = deserialize_token_creation_transaction(data, settings, verbose)
        case TxVersion.ON_CHAIN_BLUEPRINT:
            vertex = deserialize_on_chain_blueprint(data, settings, verbose)
        case TxVersion.REGULAR_BLOCK:
            vertex = deserialize_block(data, settings, verbose)
        case TxVersion.POA_BLOCK:
            vertex = deserialize_poa_block(data, settings, verbose)
        case TxVersion.MERGE_MINED_BLOCK:
            vertex = deserialize_merge_mined_block(data, verbose)
        case None:
            raise ValueError(f'Unknown tx version: {data[1]}')

    if storage is not None:
        vertex.storage = storage
    return vertex


# ---------------------------------------------------------------------------
# Per-type deserialization
# ---------------------------------------------------------------------------


def deserialize_transaction(
    data: bytes, settings: HathorSettings, verbose: VerboseCallback = None,
) -> Transaction:
    from hathor.transaction.transaction import Transaction
    from hathor.transaction.vertex_parser._common import deserialize_graph_fields
    from hathor.transaction.vertex_parser._headers import deserialize_headers
    from hathor.transaction.vertex_parser._transaction import deserialize_tx_funds

    tx = Transaction()
    deserializer = Deserializer.build_bytes_deserializer(data)
    deserialize_tx_funds(deserializer, tx, verbose=verbose)
    deserialize_graph_fields(deserializer, tx, verbose=verbose)
    (tx.nonce,) = deserializer.read_struct('!I')
    if verbose:
        verbose('nonce', tx.nonce)
    deserialize_headers(deserializer, tx, settings)
    deserializer.finalize()
    tx.update_hash()
    return tx


def deserialize_token_creation_transaction(
    data: bytes, settings: HathorSettings, verbose: VerboseCallback = None,
) -> TokenCreationTransaction:
    from hathor.transaction.token_creation_tx import TokenCreationTransaction
    from hathor.transaction.vertex_parser._common import deserialize_graph_fields
    from hathor.transaction.vertex_parser._headers import deserialize_headers
    from hathor.transaction.vertex_parser._token_creation import deserialize_token_creation_funds

    tctx = TokenCreationTransaction()
    deserializer = Deserializer.build_bytes_deserializer(data)
    deserialize_token_creation_funds(deserializer, tctx, verbose=verbose)
    deserialize_graph_fields(deserializer, tctx, verbose=verbose)
    (tctx.nonce,) = deserializer.read_struct('!I')
    if verbose:
        verbose('nonce', tctx.nonce)
    deserialize_headers(deserializer, tctx, settings)
    deserializer.finalize()
    tctx.update_hash()
    return tctx


def deserialize_on_chain_blueprint(
    data: bytes, settings: HathorSettings, verbose: VerboseCallback = None,
) -> Transaction:
    from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint
    from hathor.transaction.vertex_parser._common import deserialize_graph_fields
    from hathor.transaction.vertex_parser._headers import deserialize_headers
    from hathor.transaction.vertex_parser._on_chain_blueprint import deserialize_ocb_extra_fields
    from hathor.transaction.vertex_parser._transaction import deserialize_tx_funds

    ocb = OnChainBlueprint()
    deserializer = Deserializer.build_bytes_deserializer(data)
    deserialize_tx_funds(deserializer, ocb, verbose=verbose)
    deserialize_ocb_extra_fields(deserializer, ocb, verbose=verbose)
    deserialize_graph_fields(deserializer, ocb, verbose=verbose)
    (ocb.nonce,) = deserializer.read_struct('!I')
    if verbose:
        verbose('nonce', ocb.nonce)
    deserialize_headers(deserializer, ocb, settings)
    deserializer.finalize()
    ocb.update_hash()
    return ocb


def deserialize_block(
    data: bytes, settings: HathorSettings, verbose: VerboseCallback = None,
) -> Block:
    from hathor.transaction.block import Block
    from hathor.transaction.vertex_parser._block import deserialize_block_funds, deserialize_block_graph_fields
    from hathor.transaction.vertex_parser._headers import deserialize_headers

    block = Block()
    deserializer = Deserializer.build_bytes_deserializer(data)
    deserialize_block_funds(deserializer, block, verbose=verbose)
    deserialize_block_graph_fields(deserializer, block, verbose=verbose)
    block.nonce = int.from_bytes(deserializer.read_bytes(Block.SERIALIZATION_NONCE_SIZE), byteorder='big')
    deserialize_headers(deserializer, block, settings)
    deserializer.finalize()
    block.update_hash()
    return block


def deserialize_poa_block(
    data: bytes, settings: HathorSettings, verbose: VerboseCallback = None,
) -> Block:
    from hathor.consensus.poa.poa import SIGNER_ID_LEN
    from hathor.transaction.poa.poa_block import PoaBlock
    from hathor.transaction.vertex_parser._block import deserialize_block_funds, deserialize_poa_block_graph_fields
    from hathor.transaction.vertex_parser._headers import deserialize_headers

    poa_block = PoaBlock()
    deserializer = Deserializer.build_bytes_deserializer(data)
    deserialize_block_funds(deserializer, poa_block, verbose=verbose)
    deserialize_poa_block_graph_fields(
        deserializer, poa_block, signer_id_len=SIGNER_ID_LEN, max_signature_len=100, verbose=verbose,
    )
    poa_block.nonce = int.from_bytes(
        deserializer.read_bytes(PoaBlock.SERIALIZATION_NONCE_SIZE), byteorder='big',
    )
    deserialize_headers(deserializer, poa_block, settings)
    deserializer.finalize()
    poa_block.update_hash()
    return poa_block


def deserialize_merge_mined_block(
    data: bytes, verbose: VerboseCallback = None,
) -> MergeMinedBlock:
    from hathor.transaction.aux_pow import BitcoinAuxPow
    from hathor.transaction.merge_mined_block import MergeMinedBlock
    from hathor.transaction.vertex_parser._block import deserialize_block_funds, deserialize_block_graph_fields

    mm_block = MergeMinedBlock()
    deserializer = Deserializer.build_bytes_deserializer(data)
    deserialize_block_funds(deserializer, mm_block, verbose=verbose)
    deserialize_block_graph_fields(deserializer, mm_block, verbose=verbose)
    mm_block.aux_pow = BitcoinAuxPow.from_bytes(bytes(deserializer.read_all()))
    deserializer.finalize()
    mm_block.hash = mm_block.calculate_hash()
    return mm_block


# ---------------------------------------------------------------------------
# Component deserialization
# ---------------------------------------------------------------------------


def deserialize_tx_input(buf: bytes, *, verbose: VerboseCallback = None) -> tuple[TxInput, bytes]:
    """Deserialize a TxInput from bytes."""
    from hathor.transaction.vertex_parser._common import _deserialize_tx_input

    deserializer = Deserializer.build_bytes_deserializer(buf)
    txin = _deserialize_tx_input(deserializer, verbose=verbose)
    remaining = bytes(deserializer.read_all())
    return txin, remaining


def deserialize_tx_output(buf: bytes, *, verbose: VerboseCallback = None) -> tuple[TxOutput, bytes]:
    """Deserialize a TxOutput from bytes."""
    from hathor.transaction.vertex_parser._common import _deserialize_tx_output

    deserializer = Deserializer.build_bytes_deserializer(buf)
    txout = _deserialize_tx_output(deserializer, verbose=verbose)
    remaining = bytes(deserializer.read_all())
    return txout, remaining


def deserialize_token_info(buf: bytes, *, verbose: VerboseCallback = None) -> tuple[str, str, TokenVersion, bytes]:
    """Deserialize token info from bytes."""
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _try_tx_version(version: int) -> TxVersion | None:
    """Convert a version int to TxVersion, returning None for unknown versions."""
    try:
        return TxVersion(version)
    except (ValueError, AssertionError):
        return None
