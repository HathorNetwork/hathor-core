from typing import List, Optional

from hathor.conf import HathorSettings
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.storage import TransactionStorage

settings = HathorSettings()

GENESIS_OUTPUTS = [
    TxOutput(settings.GENESIS_TOKENS, settings.GENESIS_OUTPUT_SCRIPT),
]

BLOCK_GENESIS = Block(
    hash=bytes.fromhex('000003cf0a47d38c0407c8ffe64d47ed67e18316e43beb07c2e513f6e0b3d936'),
    data=b'',
    nonce=338994,
    timestamp=1560920000,
    weight=settings.MIN_BLOCK_WEIGHT,
    outputs=GENESIS_OUTPUTS,
)

TX_GENESIS1 = Transaction(
    hash=bytes.fromhex('000250e65d8cb4044a4f5659720179e5faeb13d01476a3fb283c7bb8e57e4d0f'),
    nonce=596,
    timestamp=1560920001,
    weight=settings.MIN_TX_WEIGHT,
)

TX_GENESIS2 = Transaction(
    hash=bytes.fromhex('000039762550478005083fcab58a465b3d83148d067e4c827a96b5eec1635401'),
    nonce=22773,
    timestamp=1560920002,
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


def get_genesis_transactions(tx_storage: Optional[TransactionStorage]) -> List[BaseTransaction]:
    genesis = []
    for tx in GENESIS:
        tx2 = tx.clone()
        tx2.storage = tx_storage
        genesis.append(tx2)
    return genesis
