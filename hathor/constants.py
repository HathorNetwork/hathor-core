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

HATHOR_TOKEN_UID = b'\x00'

# Average time between blocks.
AVG_TIME_BETWEEN_BLOCKS = 64

# Maximum distance between two consecutive blocks (in seconds), except for genesis.
# This prevent some DoS attacks exploiting the calculation of the score of a side chain.
# P(t > T) = 1/e^30 = 9.35e-14
MAX_DISTANCE_BETWEEN_BLOCKS = 30 * AVG_TIME_BETWEEN_BLOCKS

# Number of blocks to be found with the same hash algorithm as `block`.
# The bigger it is, the smaller the variance of the hash rate estimator is.
BLOCK_DIFFICULTY_N_BLOCKS = 120

# Maximum change in difficulty between consecutive blocks.
#
# The variance of the hash rate estimator is high when the hash rate is increasing
# or decreasing. Many times it will overreact and increase/decrease the weight too
# much. This limit is used to make the weight change more smooth.
BLOCK_DIFFICULTY_MAX_DW = 0.25

# Maximum depth looking for blocks with the same hash algorithm.
# The probability of finding N blocks when the max depth is K*N is:
# P(x >= N) = 1 - norm.cdf((A - K) * sqrt(N) / sqrt(K * (A - 1)))
# Where A is the number of hash algorithms available.
#
# For N=120 and A=2, we have that K=3 implies P(x >= N) = 0.9999999998730186,
# while K = 2 implies P(x >= N) = 0.5.
#
# Thus, K=3 is the least value to find all the 120 most of the times.
BLOCK_DIFFICULTY_MAX_DEPTH = 3 * BLOCK_DIFFICULTY_N_BLOCKS
