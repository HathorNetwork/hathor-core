from hathor.transaction import Transaction, TxOutput
from hathor.transaction.block import Block


def genesis_transactions(tx_storage):
    TX_GENESIS1 = Transaction(
        hash=bytes.fromhex('000000fca35d25c2b575bec054308a0c24c3d0b798f1268bec562ec160ce0f68'),
        nonce=17262397,
        timestamp=1533643201,
        weight=24,
        height=1,
        storage=tx_storage,
    )

    TX_GENESIS2 = Transaction(
        hash=bytes.fromhex('00000040ec1ee714cc1a8b5e49fced848484ab8081b97394c93da1425c4e6179'),
        nonce=15665735,
        timestamp=1533643202,
        weight=24,
        height=1,
        storage=tx_storage,
    )

    GENESIS_OUTPUT = TxOutput(1000, bytes.fromhex('98f12b659336a1874ddbae37837fa8a39f66b53d'))
    BLOCK_GENESIS = Block(
        hash=bytes.fromhex('0000084e8ab42ae037210690854a3452ba6c8b4c0e02567157003ea4a364008a'),
        nonce=3508191,
        timestamp=1533643200,
        weight=24,
        height=1,
        outputs=[GENESIS_OUTPUT],
        storage=tx_storage,
    )
    return [
        BLOCK_GENESIS,
        TX_GENESIS1,
        TX_GENESIS2
    ]
