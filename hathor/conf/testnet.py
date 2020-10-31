# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from hathor.conf.settings import HathorSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x49',
    MULTISIG_VERSION_BYTE=b'\x87',
    NETWORK_NAME='testnet-foxtrot',
    BOOTSTRAP_DNS=['foxtrot.testnet.hathor.network'],
    # Genesis stuff
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a914a584cf48b161e4a49223ed220df30037ab740e0088ac'),
    GENESIS_TIMESTAMP=1577836800,
    GENESIS_BLOCK_NONCE=826272,
    GENESIS_BLOCK_HASH=bytes.fromhex('0000033139d08176d1051fb3a272c3610457f0c7f686afbe0afe3d37f966db85'),
    GENESIS_TX1_NONCE=190,
    GENESIS_TX1_HASH=bytes.fromhex('00e161a6b0bee1781ea9300680913fb76fd0fac4acab527cd9626cc1514abdc9'),
    GENESIS_TX2_NONCE=115,
    GENESIS_TX2_HASH=bytes.fromhex('00975897028ceb037307327c953f5e7ad4d3f42402d71bd3d11ecb63ac39f01a'),
    # tx weight parameters. With these settings, tx weight is always 8
    MIN_TX_WEIGHT_K=0,
    MIN_TX_WEIGHT_COEFFICIENT=0,
    MIN_TX_WEIGHT=8,
)
