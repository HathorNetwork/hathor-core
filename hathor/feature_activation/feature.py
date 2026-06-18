# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from enum import StrEnum, unique


@unique
class Feature(StrEnum):
    """
    An enum containing all features that participate in the feature activation process, past or future, activated
    or not, for all networks. Features should NOT be removed from this enum, to preserve history. Their values
    should NOT be changed either, as configuration uses them for setting feature activation criteria.
    """

    # These NOP features are used in tests
    NOP_FEATURE_1 = 'NOP_FEATURE_1'
    NOP_FEATURE_2 = 'NOP_FEATURE_2'
    NOP_FEATURE_3 = 'NOP_FEATURE_3'

    INCREASE_MAX_MERKLE_PATH_LENGTH = 'INCREASE_MAX_MERKLE_PATH_LENGTH'
    COUNT_CHECKDATASIG_OP = 'COUNT_CHECKDATASIG_OP'
    NANO_CONTRACTS = 'NANO_CONTRACTS'

    FAILED_FEE_TOKENS = 'FAILED_FEE_TOKENS'
    FEE_TOKENS = 'FEE_TOKENS'

    FAILED_OPCODES_V2 = 'FAILED_OPCODES_V2'
    OPCODES_V2 = 'OPCODES_V2'

    RESTRICT_DUP_ACTIONS = 'RESTRICT_DUP_ACTIONS'
    REDUCE_DAA_TARGET = 'REDUCE_DAA_TARGET'

    SHIELDED_TRANSACTIONS = 'SHIELDED_TRANSACTIONS'
    TOKEN_AMOUNT_V2 = 'TOKEN_AMOUNT_V2'
