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
from hathor.feature_activation.settings import Settings as FeatureActivationSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x28',
    MULTISIG_VERSION_BYTE=b'\x64',
    NETWORK_NAME='unittests',
    BLOCKS_PER_HALVING=2 * 60,
    MIN_BLOCK_WEIGHT=2,
    MIN_TX_WEIGHT=2,
    MIN_SHARE_WEIGHT=2,
    MAX_TX_WEIGHT_DIFF=25.0,
    BLOCK_DIFFICULTY_N_BLOCKS=20,
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a914fd05059b6006249543b82f36876a17c73fd2267b88ac'),
    GENESIS_BLOCK_NONCE=0,
    GENESIS_BLOCK_HASH=bytes.fromhex('339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792'),
    GENESIS_TX1_NONCE=6,
    GENESIS_TX1_HASH=bytes.fromhex('16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952'),
    GENESIS_TX2_NONCE=2,
    GENESIS_TX2_HASH=bytes.fromhex('33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'),
    REWARD_SPEND_MIN_BLOCKS=10,
    SLOW_ASSERTS=True,
    MAX_TX_WEIGHT_DIFF_ACTIVATION=0.0,
    FEATURE_ACTIVATION=FeatureActivationSettings(
        evaluation_interval=4,
        max_signal_bits=4,
        default_threshold=3
    ),
    ENABLE_NANO_CONTRACTS=True,
    BLUEPRINTS={
        bytes.fromhex('3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595'): 'Bet'
    },
)
