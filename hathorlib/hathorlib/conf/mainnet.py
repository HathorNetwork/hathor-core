"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

from hathorlib.conf.settings import HathorSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x28',
    MULTISIG_VERSION_BYTE=b'\x64',
    NETWORK_NAME='mainnet',
)
