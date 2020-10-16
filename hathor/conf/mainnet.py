from hathor.conf.settings import HathorSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x28',
    MULTISIG_VERSION_BYTE=b'\x64',
    NETWORK_NAME='mainnet',
    BOOTSTRAP_DNS=['mainnet.hathor.network'],
    ENABLE_PEER_WHITELIST=True,
    # Genesis stuff
    # output addr: HJB2yxxsHtudGGy3jmVeadwMfRi2zNCKKD
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a9147fd4ae0e4fb2d2854e76d359029d8078bb99649e88ac'),
    GENESIS_TIMESTAMP=1578075305,
    GENESIS_BLOCK_NONCE=2591358,
    GENESIS_BLOCK_HASH=bytes.fromhex('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc'),
    GENESIS_TX1_NONCE=7715,
    GENESIS_TX1_HASH=bytes.fromhex('0002d4d2a15def7604688e1878ab681142a7b155cbe52a6b4e031250ae96db0a'),
    GENESIS_TX2_NONCE=3769,
    GENESIS_TX2_HASH=bytes.fromhex('0002ad8d1519daaddc8e1a37b14aac0b045129c01832281fb1c02d873c7abbf9'),
)
