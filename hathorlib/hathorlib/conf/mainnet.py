# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathorlib.conf.settings import HathorSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x28',
    MULTISIG_VERSION_BYTE=b'\x64',
    NETWORK_NAME='mainnet',
    MAX_TX_WEIGHT_DIFF=1.0,
    MAX_TX_WEIGHT_DIFF_ACTIVATION=35.0,
)
