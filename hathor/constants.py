TOKENS_PER_BLOCK = 20

DECIMAL_PLACES = 2

GENESIS_TOKEN_UNITS = 2 * (10**9)  # 2B

GENESIS_TOKENS = GENESIS_TOKEN_UNITS * (10**DECIMAL_PLACES)  # 200B

# Output value is 4 bytes. This is the maximum value
MAX_VALUE = 2**32 - 1

# Version byte of the address in P2PKH
P2PKH_VERSION_BYTE = b'\x00'

# Version byte of the address in MultiSig
MULTISIG_VERSION_BYTE = b'\x05'

# Weight of genesis and minimum weight of a tx/block
MIN_WEIGHT = 14
