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

from typing import List, Optional

from hathor.conf import HathorSettings
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.storage import TransactionStorage

settings = HathorSettings()

BLOCK_GENESIS = Block(
    hash=settings.GENESIS_BLOCK_HASH,
    nonce=settings.GENESIS_BLOCK_NONCE,
    timestamp=settings.GENESIS_TIMESTAMP,
    weight=settings.MIN_BLOCK_WEIGHT,
    outputs=[
        TxOutput(settings.GENESIS_TOKENS, settings.GENESIS_OUTPUT_SCRIPT),
    ],
)

TX_GENESIS1 = Transaction(
    hash=settings.GENESIS_TX1_HASH,
    nonce=settings.GENESIS_TX1_NONCE,
    timestamp=settings.GENESIS_TIMESTAMP + 1,
    weight=settings.MIN_TX_WEIGHT,
)

TX_GENESIS2 = Transaction(
    hash=settings.GENESIS_TX2_HASH,
    nonce=settings.GENESIS_TX2_NONCE,
    timestamp=settings.GENESIS_TIMESTAMP + 2,
    weight=settings.MIN_TX_WEIGHT,
)

GENESIS = [BLOCK_GENESIS, TX_GENESIS1, TX_GENESIS2]


def _get_genesis_hash() -> bytes:
    import hashlib
    h = hashlib.sha256()
    for tx in GENESIS:
        tx_hash = tx.hash
        assert tx_hash is not None
        h.update(tx_hash)
    return h.digest()


GENESIS_HASH = _get_genesis_hash()


def _get_genesis_transactions_unsafe(tx_storage: Optional[TransactionStorage]) -> List[BaseTransaction]:
    """You shouldn't get genesis directly. Please, get it from your storage instead."""
    genesis = []
    for tx in GENESIS:
        tx2 = tx.clone()
        tx2.storage = tx_storage
        genesis.append(tx2)
    return genesis


def is_genesis(hash_bytes: bytes) -> bool:
    """Check whether hash is from a genesis transaction."""
    for tx in GENESIS:
        if hash_bytes == tx.hash:
            return True
    return False
