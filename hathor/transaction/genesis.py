from typing import List, Optional

from hathor.conf import HathorSettings
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.storage import TransactionStorage

settings = HathorSettings()

TX_GENESIS1 = Transaction(
    hash=bytes.fromhex('0001e887c7b5ec3b4e57033d849a80d8bccbe3a749abfa87cc31c663530f3f4e'),
    nonce=23519,
    timestamp=1539271482,
    weight=settings.MIN_TX_WEIGHT,
)

TX_GENESIS2 = Transaction(
    hash=bytes.fromhex('00029b7f8051f6ebdc0338d02d4a8cfbd662500ee03224bbee75a6f2da0350b0'),
    nonce=11402,
    timestamp=1539271483,
    weight=settings.MIN_TX_WEIGHT,
)

GENESIS_OUTPUTS = [
    TxOutput(settings.GENESIS_TOKENS, settings.GENESIS_OUTPUT_SCRIPT),
]
BLOCK_GENESIS = Block(
    hash=bytes.fromhex('000164e1e7ec7700a18750f9f50a1a9b63f6c7268637c072ae9ee181e58eb01b'),
    data=b'',
    nonce=60315,
    timestamp=1539271481,
    weight=settings.MIN_BLOCK_WEIGHT,
    outputs=GENESIS_OUTPUTS,
)
GENESIS = [BLOCK_GENESIS, TX_GENESIS1, TX_GENESIS2]


def get_genesis_transactions(tx_storage: Optional[TransactionStorage]) -> List[BaseTransaction]:
    genesis = []
    for tx in GENESIS:
        tx2 = tx.clone()
        tx2.storage = tx_storage
        genesis.append(tx2)
    return genesis
