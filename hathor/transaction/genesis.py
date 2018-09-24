from hathor.transaction import Transaction, TxOutput
from hathor.transaction.block import Block


def genesis_transactions(tx_storage):
    TX_GENESIS1 = Transaction(
        hash=bytes.fromhex('000000c3ca3465d98bb5c69464d983556f9fc1a30d72f7b288ce8f13609573b7'),
        nonce=17720004,
        timestamp=1533643201,
        weight=24,
        height=1,
        storage=tx_storage,
    )

    TX_GENESIS2 = Transaction(
        hash=bytes.fromhex('00000018d7f4f93eacb98a08a11f1ab61c35ad3429e3821fd605ec110037eb1b'),
        nonce=15965363,
        timestamp=1533643202,
        weight=24,
        height=1,
        storage=tx_storage,
    )

    GENESIS_OUTPUT = TxOutput(1000, bytes.fromhex('76a91498f12b659336a1874ddbae37837fa8a39f66b53d88ac'))
    BLOCK_GENESIS = Block(
        hash=bytes.fromhex('00000072a6939650274b05d9d76f683654ecabd2620dc5c08bc4d832aa8b4909'),
        nonce=14767626,
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
