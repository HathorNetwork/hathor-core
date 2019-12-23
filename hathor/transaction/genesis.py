from typing import List, Optional

from hathor.conf import HathorSettings
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.storage import TransactionStorage

settings = HathorSettings()

GENESIS_OUTPUTS = [
    TxOutput(settings.GENESIS_TOKENS, settings.GENESIS_OUTPUT_SCRIPT),
]

BLOCK_GENESIS = Block(
    hash=bytes.fromhex('000007eb968a6cdf0499e2d033faf1e163e0dc9cf41876acad4d421836972038'),
    data=b'',
    nonce=3526202,
    timestamp=1572636343,
    weight=settings.MIN_BLOCK_WEIGHT,
    outputs=GENESIS_OUTPUTS,
)

TX_GENESIS1 = Transaction(
    hash=bytes.fromhex('00025d75e44804a6a6a099f4320471c864b38d37b79b496ee26080a2a1fd5b7b'),
    nonce=12595,
    timestamp=1572636344,
    weight=settings.MIN_TX_WEIGHT,
)

TX_GENESIS2 = Transaction(
    hash=bytes.fromhex('0002c187ab30d4f61c11a5dc43240bdf92dba4d19f40f1e883b0a5fdac54ef53'),
    nonce=21301,
    timestamp=1572636345,
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
