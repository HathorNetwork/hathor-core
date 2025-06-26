# Copyright 2022 Hathor Labs
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
    NETWORK_NAME='nano-testnet-bravo',
    BOOTSTRAP_DNS=['bravo.nano-testnet.hathor.network'],
    # Genesis stuff
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a91478e804bf8aa68332c6c1ada274ac598178b972bf88ac'),
    GENESIS_BLOCK_TIMESTAMP=1750978888,
    GENESIS_BLOCK_NONCE=896384,
    GENESIS_BLOCK_HASH=bytes.fromhex('000003076f294c2c93d8cc48f68b6c93087361ca78c54faa91daaffde84ba916'),
    GENESIS_TX1_NONCE=16,
    GENESIS_TX1_HASH=bytes.fromhex('001c9a3e8810bc3389b0fd3cfb118e9190f95bd5bf313a9575a4663d0a80af2d'),
    GENESIS_TX2_NONCE=154,
    GENESIS_TX2_HASH=bytes.fromhex('002fecfce5e78047f9b967a27b1b2436c3fea17e24c770d59421bacdcadda0ea'),
    # tx weight parameters. With these settings, tx weight is always 8
    MIN_TX_WEIGHT_K=0,
    MIN_TX_WEIGHT_COEFFICIENT=0,
    MIN_TX_WEIGHT=8,
    CHECKPOINTS=[],
    ENABLE_NANO_CONTRACTS=True,
    ENABLE_ON_CHAIN_BLUEPRINTS=True,
    NC_ON_CHAIN_BLUEPRINT_ALLOWED_ADDRESSES=[
        'WWFiNeWAFSmgtjm4ht2MydwS5GY3kMJsEK',
    ],
)
