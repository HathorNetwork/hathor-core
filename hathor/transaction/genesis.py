from typing import List, Optional

from hathor.conf import HathorSettings
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.storage import TransactionStorage

settings = HathorSettings()

TX_GENESIS1 = Transaction(
    hash=bytes.fromhex('0001d3c338d4f8f2e4f013840a728180f9a4f19e1d47acdf238e6e9525f2334e'),
    nonce=728,
    timestamp=1559900001,
    weight=settings.MIN_TX_WEIGHT,
)

TX_GENESIS2 = Transaction(
    hash=bytes.fromhex('0001beaab8d90419b561d7df8e28ffd55a52829fd763ecf4b50b5ecc37fb6d90'),
    nonce=16273,
    timestamp=1559900002,
    weight=settings.MIN_TX_WEIGHT,
)

GENESIS_OUTPUTS = [
    TxOutput(settings.GENESIS_TOKENS, settings.GENESIS_OUTPUT_SCRIPT),
]
BLOCK_GENESIS = Block(
    hash=bytes.fromhex('000003dccc6e4422a8f5fc721b42b4c26b157e1fb577da74350865d549c7f92c'),
    data=b'',
    nonce=1984075,
    timestamp=1559900000,
    weight=settings.MIN_BLOCK_WEIGHT,
    outputs=GENESIS_OUTPUTS,
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
