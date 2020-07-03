from hathor.conf.settings import HathorSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x49',
    MULTISIG_VERSION_BYTE=b'\x87',
    NETWORK_NAME='testnet-echo',
    BOOTSTRAP_DNS=['echo.testnet.hathor.network'],
    # Genesis stuff
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a914a584cf48b161e4a49223ed220df30037ab740e0088ac'),
    GENESIS_TIMESTAMP=1577836800,
    GENESIS_BLOCK_NONCE=3526202,
    GENESIS_BLOCK_HASH=bytes.fromhex('000007eb968a6cdf0499e2d033faf1e163e0dc9cf41876acad4d421836972038'),
    GENESIS_TX1_NONCE=12595,
    GENESIS_TX1_HASH=bytes.fromhex('00025d75e44804a6a6a099f4320471c864b38d37b79b496ee26080a2a1fd5b7b'),
    GENESIS_TX2_NONCE=21301,
    GENESIS_TX2_HASH=bytes.fromhex('0002c187ab30d4f61c11a5dc43240bdf92dba4d19f40f1e883b0a5fdac54ef53'),
    # tx weight parameters. With these settings, tx weight is always 8
    MIN_TX_WEIGHT_K=0,
    MIN_TX_WEIGHT_COEFFICIENT=0,
    MIN_TX_WEIGHT=8,
)
