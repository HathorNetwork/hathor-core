from hathor.transaction import Transaction, TxOutput
from hathor.transaction.block import Block


def genesis_transactions(tx_storage):
    TX_GENESIS1 = Transaction(
        hash=bytes.fromhex('000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a5533849'),
        nonce=10887893,
        timestamp=1533643201,
        weight=24,
        height=1,
        storage=tx_storage,
    )

    TX_GENESIS2 = Transaction(
        hash=bytes.fromhex('0000001df6f77892cd562a2d7829bc17d0130546edfc6a81e0a431af4b8aa51e'),
        nonce=4730590,
        timestamp=1533643202,
        weight=24,
        height=1,
        storage=tx_storage,
    )

    GENESIS_OUTPUT = TxOutput(1000, bytes.fromhex('98f12b659336a1874ddbae37837fa8a39f66b53d'))
    BLOCK_GENESIS = Block(
        hash=bytes.fromhex('000000a0f82cfee5431e03b071364970861ffa1b0633f73ca7f462987ec34195'),
        nonce=3358544,
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
