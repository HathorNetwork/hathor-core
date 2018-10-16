from hathor.transaction import Transaction, TxOutput
from hathor.transaction.block import Block


def genesis_transactions(tx_storage):
    TX_GENESIS1 = Transaction(
        hash=bytes.fromhex('0001569c85fffa5782c3979e7d68dce1d8d84772505a53ddd76d636585f3977d'),
        nonce=19300,
        timestamp=1539271482,
        weight=14,
        height=1,
        storage=tx_storage,
    )

    TX_GENESIS2 = Transaction(
        hash=bytes.fromhex('0000810b22f0cdc3ac6d978a4c80ea46f831b74765fefea2595cc6d4b00e207a'),
        nonce=22587,
        timestamp=1539271483,
        weight=14,
        height=1,
        storage=tx_storage,
    )

    GENESIS_OUTPUT = TxOutput(1000, bytes.fromhex('76a91498f12b659336a1874ddbae37837fa8a39f66b53d88ac'))
    BLOCK_GENESIS = Block(
        hash=bytes.fromhex('000084c3c31c8d3a994ec0de790526ce508a0ede578f208072a7715fe0692309'),
        nonce=47477,
        timestamp=1539271481,
        weight=14,
        height=1,
        outputs=[GENESIS_OUTPUT],
        storage=tx_storage,
    )
    return [
        BLOCK_GENESIS,
        TX_GENESIS1,
        TX_GENESIS2
    ]
