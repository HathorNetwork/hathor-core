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

"""Shared utilities for dry-run block resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionIsNotABlock

if TYPE_CHECKING:
    from hathor.transaction import Block
    from hathor.transaction.storage import TransactionStorage


class DryRunValidationError(Exception):
    """Raised when dry-run input validation fails (e.g., invalid hash format, genesis block)."""
    pass


class DryRunNotFoundError(Exception):
    """Raised when a referenced block or transaction is not found."""
    pass


@dataclass(frozen=True)
class DryRunTarget:
    """Result of resolving a dry-run target block."""
    block: 'Block'
    target_tx_hash: Optional[bytes] = None


def resolve_block_for_dry_run(
    tx_storage: 'TransactionStorage',
    *,
    block_hash: Optional[str] = None,
    tx_hash: Optional[str] = None,
) -> DryRunTarget:
    """Resolve and validate a block for dry-run execution.

    Args:
        tx_storage: The transaction storage to look up blocks/txs.
        block_hash: Hex-encoded block hash (mutually exclusive with tx_hash).
        tx_hash: Hex-encoded transaction hash (mutually exclusive with block_hash).

    Returns:
        DryRunTarget with the resolved block and optional target tx hash.

    Raises:
        DryRunValidationError: For invalid input (bad hash, genesis, voided, not NC).
        DryRunNotFoundError: When the referenced block or transaction is not found.
    """
    if tx_hash:
        return _resolve_via_tx(tx_storage, tx_hash)
    elif block_hash:
        return _resolve_via_block(tx_storage, block_hash)
    else:
        raise DryRunValidationError('Must specify either block_hash or tx_hash')


def _resolve_via_tx(tx_storage: 'TransactionStorage', tx_hash_hex: str) -> DryRunTarget:
    """Resolve block via a transaction's first_block."""
    try:
        tx_hash_bytes = bytes.fromhex(tx_hash_hex)
    except ValueError:
        raise DryRunValidationError(f'Invalid tx_hash: {tx_hash_hex}')

    try:
        tx = tx_storage.get_transaction(tx_hash_bytes)
    except TransactionDoesNotExist:
        raise DryRunNotFoundError(f'Transaction not found: {tx_hash_hex}')

    if not tx.is_nano_contract():
        raise DryRunValidationError('Transaction is not a nano contract')

    tx_meta = tx.get_metadata()
    if tx_meta.first_block is None:
        raise DryRunValidationError('Transaction has no first_block')

    try:
        block = tx_storage.get_block(tx_meta.first_block)
    except (TransactionDoesNotExist, TransactionIsNotABlock):
        raise DryRunNotFoundError(f'Block not found: {tx_meta.first_block.hex()}')

    _validate_block(block)
    return DryRunTarget(block=block, target_tx_hash=tx_hash_bytes)


def _resolve_via_block(tx_storage: 'TransactionStorage', block_hash_hex: str) -> DryRunTarget:
    """Resolve block directly by hash."""
    try:
        block_hash_bytes = bytes.fromhex(block_hash_hex)
    except ValueError:
        raise DryRunValidationError(f'Invalid block_hash: {block_hash_hex}')

    try:
        block = tx_storage.get_block(block_hash_bytes)
    except (TransactionDoesNotExist, TransactionIsNotABlock):
        raise DryRunNotFoundError(f'Block not found: {block_hash_hex}')

    _validate_block(block)
    return DryRunTarget(block=block)


def _validate_block(block: 'Block') -> None:
    """Validate that a block is suitable for dry-run execution."""
    block_meta = block.get_metadata()
    if block_meta.voided_by:
        raise DryRunValidationError('Block is not on best chain (voided)')
    if block.is_genesis:
        raise DryRunValidationError('Cannot dry-run genesis block')
