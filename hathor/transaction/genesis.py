# Copyright 2021 Hathor Labs
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

from typing import TYPE_CHECKING

from hathor.conf.settings import HathorSettings
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


def get_genesis_block(settings: HathorSettings) -> Block:
    """Return the genesis block."""
    return Block(
        hash=settings.GENESIS_BLOCK_HASH,
        nonce=settings.GENESIS_BLOCK_NONCE,
        timestamp=settings.GENESIS_TIMESTAMP,
        weight=settings.MIN_BLOCK_WEIGHT,
        outputs=[
            TxOutput(settings.GENESIS_TOKENS, settings.GENESIS_OUTPUT_SCRIPT),
        ],
    )


def get_genesis_tx1(settings: HathorSettings) -> Transaction:
    """Return the genesis tx1."""
    return Transaction(
        hash=settings.GENESIS_TX1_HASH,
        nonce=settings.GENESIS_TX1_NONCE,
        timestamp=settings.GENESIS_TIMESTAMP + 1,
        weight=settings.MIN_TX_WEIGHT,
    )


def get_genesis_tx2(settings: HathorSettings) -> Transaction:
    """Return the genesis tx2."""
    return Transaction(
        hash=settings.GENESIS_TX2_HASH,
        nonce=settings.GENESIS_TX2_NONCE,
        timestamp=settings.GENESIS_TIMESTAMP + 2,
        weight=settings.MIN_TX_WEIGHT,
    )


def get_all_genesis(settings: HathorSettings) -> list[BaseTransaction]:
    """Return all genesis vertices."""
    return [
        get_genesis_block(settings),
        get_genesis_tx1(settings),
        get_genesis_tx2(settings)
    ]


def get_all_genesis_hashes(settings: HathorSettings) -> list[bytes]:
    """Return all genesis hashes."""
    return [
        settings.GENESIS_BLOCK_HASH,
        settings.GENESIS_TX1_HASH,
        settings.GENESIS_TX2_HASH
    ]


def get_genesis_hash(settings: HathorSettings) -> bytes:
    """Return a single hash representing all genesis."""
    import hashlib
    h = hashlib.sha256()
    for tx_hash in get_all_genesis_hashes(settings):
        h.update(tx_hash)
    return h.digest()


def is_genesis(hash_bytes: bytes, *, settings: HathorSettings) -> bool:
    """Check whether hash is from a genesis transaction."""
    return hash_bytes in get_all_genesis_hashes(settings)
