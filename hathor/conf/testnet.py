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

from hathor.checkpoint import Checkpoint as cp
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.settings import Settings as FeatureActivationSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x49',
    MULTISIG_VERSION_BYTE=b'\x87',
    NETWORK_NAME='testnet-golf',
    BOOTSTRAP_DNS=['golf.testnet.hathor.network'],
    # Genesis stuff
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a914a584cf48b161e4a49223ed220df30037ab740e0088ac'),
    GENESIS_BLOCK_TIMESTAMP=1577836800,
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
    CHECKPOINTS=[
        cp(100_000, bytes.fromhex('0000007ece4c7830169f360ed11c51b776e1b72bf0060e6e5b325ca8be474ac5')),
        cp(200_000, bytes.fromhex('00000113ecd4b666116abf3d3f05ad509d903d6b456a1e8c35e46a9e426af11a')),
        cp(300_000, bytes.fromhex('000000e42df13e4e7490cee98f303cb3b0ca33f362af180c5f7df740c98699d9')),
        cp(400_000, bytes.fromhex('000000e9a748b34fc4d662d88bb36ef2a033ba129960924208be14eccdac1a65')),
        cp(500_000, bytes.fromhex('000000b5c4572d7b85e585849540ece44b73948c5cdbc6f17a9a3a77fbd0f29a')),
        cp(600_000, bytes.fromhex('000000f6743ba3d67e51d7adc21821b8263726ce3bc86010d5e1a905bf2531dc')),
        cp(700_000, bytes.fromhex('0000008fda01c9e5fd6f99a5461e6dbf1039cba38cc8d0fc738a097d71caa968')),
        cp(800_000, bytes.fromhex('000000397af32fcc4eeb6985d96326c1ff4644792631872a00394688b1782af5')),
        cp(900_000, bytes.fromhex('00000097ae405036614f4335ad0e631df8fc5f7434e82c3421627e2fea4e1830')),
        cp(1_000_000, bytes.fromhex('000000145ba662cdee0d72034658f93a0a3a4568d5ba5083ff09013ca1e6556c')),
        cp(1_100_000, bytes.fromhex('000000404e6ff6a23695a6ffe712ce1c4efc02e75bbc11c3129f4c2377b07743')),
        cp(1_200_000, bytes.fromhex('0000003be5fae5bb2c9ceaed589d172bcd9e74ca6c8d7d2ca06567f65cea7c9b')),
        cp(1_300_000, bytes.fromhex('0000000000007d39de6e781c377bc202213b0b5b60db14c13d0b16e06d6fd5ac')),
        cp(1_400_000, bytes.fromhex('000000000df9cb786c68a643a52a67c22ab54e8b8e41cbe9b761133f6c8abbfe')),
        cp(1_500_000, bytes.fromhex('000000000c3591805f4748480b59ac1788f754fc004930985a487580e2b5de8f')),
        cp(1_600_000, bytes.fromhex('00000000060adfdfd7d488d4d510b5779cf35a3c50df7bcff941fbb6957be4d2')),
    ],
    FEATURE_ACTIVATION=FeatureActivationSettings(
        enable_usage=True,
        default_threshold=30240,
        features={
            Feature.NOP_FEATURE_1: Criteria(
              bit=0,
              start_height=3_144_960,  # N (right now the best block is 3093551 on testnet)
              timeout_height=3_225_600,  # N + 2 * 40320 (4 weeks after the start)
              minimum_activation_height=3_265_920,  # N + 3 * 40320 (6 weeks after the start)
              lock_in_on_timeout=False,
              version='0.56.0',
              signal_support_by_default=True
            ),
            Feature.NOP_FEATURE_2: Criteria(
              bit=1,
              start_height=3_144_960,  # N (right now the best block is 3093551 on testnet)
              timeout_height=3_225_600,  # N + 2 * 40320 (4 weeks after the start)
              minimum_activation_height=0,
              lock_in_on_timeout=True,
              version='0.56.0',
              signal_support_by_default=False
            ),
            Feature.NOP_FEATURE_3: Criteria(
              bit=2,
              start_height=3_144_960,  # N (right now the best block is 3093551 on testnet)
              timeout_height=3_225_600,  # N + 2 * 40320 (4 weeks after the start)
              minimum_activation_height=0,
              lock_in_on_timeout=False,
              version='0.56.0',
              signal_support_by_default=False
            ),
            Feature.NOP_FEATURE_4: Criteria(
              bit=0,
              start_height=3_386_880,  # N (right now the best block is 3_346_600 on testnet)
              timeout_height=3_467_520,  # N + 2 * 40320 (4 weeks after the start)
              minimum_activation_height=3_507_840,  # N + 3 * 40320 (6 weeks after the start)
              lock_in_on_timeout=False,
              version='0.57.0',
              signal_support_by_default=True
            ),
            Feature.NOP_FEATURE_5: Criteria(
              bit=1,
              start_height=3_386_880,  # N (right now the best block is 3_346_600 on testnet)
              timeout_height=3_467_520,  # N + 2 * 40320 (4 weeks after the start)
              minimum_activation_height=0,
              lock_in_on_timeout=True,
              version='0.57.0',
              signal_support_by_default=False
            ),
            Feature.NOP_FEATURE_6: Criteria(
              bit=2,
              start_height=3_386_880,  # N (right now the best block is 3_346_600 on testnet)
              timeout_height=3_467_520,  # N + 2 * 40320 (4 weeks after the start)
              minimum_activation_height=0,
              lock_in_on_timeout=False,
              version='0.57.0',
              signal_support_by_default=False
            )
        }
    )
)
