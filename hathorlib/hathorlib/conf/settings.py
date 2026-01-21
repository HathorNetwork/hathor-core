"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

from typing import NamedTuple


class HathorSettings(NamedTuple):
    # Name of the network: "mainnet", "testnet-alpha", "testnet-bravo", ...
    NETWORK_NAME: str

    # Version byte of the address in P2PKH
    P2PKH_VERSION_BYTE: bytes

    # Version byte of the address in MultiSig
    MULTISIG_VERSION_BYTE: bytes

    # HTR Token UID
    HATHOR_TOKEN_UID: bytes = b'\x00'

    # Maximum number of characters in a token name
    MAX_LENGTH_TOKEN_NAME: int = 30

    # Maximum number of characters in a token symbol
    MAX_LENGTH_TOKEN_SYMBOL: int = 5

    # Name of the Hathor token
    HATHOR_TOKEN_NAME: str = 'Hathor'

    # Symbol of the Hathor token
    HATHOR_TOKEN_SYMBOL: str = 'HTR'

    # Number of decimal places for the Hathor token
    DECIMAL_PLACES: int = 2

    # Minimum weight of a tx
    MIN_TX_WEIGHT: int = 14

    # Multiplier coefficient to adjust the minimum weight of a normal tx to 18
    MIN_TX_WEIGHT_COEFFICIENT: float = 1.6

    # Amount in which tx min weight reaches the middle point between the minimum and maximum weight
    MIN_TX_WEIGHT_K: int = 100

    # Maximum size of the tx output's script allowed for a tx to be standard
    PUSHTX_MAX_OUTPUT_SCRIPT_SIZE: int = 256

    # Maximum number of tx outputs of Data Script type
    MAX_DATA_SCRIPT_OUTPUTS: int = 25

    # Max length in bytes allowed for on-chain blueprint code after decompression, 240KB (not KiB)
    NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_UNCOMPRESSED: int = 240_000

    # Max length in bytes allowed for on-chain blueprint code inside the transaction, 24KB (not KiB)
    NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_COMPRESSED: int = 24_000
