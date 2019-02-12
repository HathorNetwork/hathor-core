TOKENS_PER_BLOCK = 20

DECIMAL_PLACES = 2

GENESIS_TOKEN_UNITS = 2 * (10**9)  # 2B

GENESIS_TOKENS = GENESIS_TOKEN_UNITS * (10**DECIMAL_PLACES)  # 200B

# Version byte of the address in P2PKH
P2PKH_VERSION_BYTE = b'\x00'

# Version byte of the address in MultiSig
MULTISIG_VERSION_BYTE = b'\x05'

# Weight of genesis and minimum weight of a tx/block
MIN_BLOCK_WEIGHT = 14
MIN_TX_WEIGHT = 14

HATHOR_TOKEN_UID = b'\x00'

# Maximum distance between two consecutive blocks (in seconds), except for genesis.
# This prevent some DoS attacks exploiting the calculation of the score of a side chain.
MAX_DISTANCE_BETWEEN_BLOCKS = 30*64  # P(t > T) = 1/e^30 = 9.35e-14

# Number of bytes that each transaction type nonce have
BLOCK_NONCE_BYTES = 16
TX_NONCE_BYTES = 4

# Size limit in bytes for Block data field
BLOCK_DATA_MAX_SIZE = 100
