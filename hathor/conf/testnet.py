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
        cp(1_700_000, bytes.fromhex('0000000007afc04aebad15b14fcd93c1b5193dc503b190433f55be8c218b6d12')),
        cp(1_800_000, bytes.fromhex('00000000126f16af2ba934a60cf8f2da32d3ed2688c56ce8ff477e483a3ffc42')),
        cp(1_900_000, bytes.fromhex('0000000005d2a2ba2231663187b460396189af0ffca7b2e93fccc85cde04cbdc')),
        cp(2_000_000, bytes.fromhex('000000000009a8451ff2d5ec54951d717da2766aedb3131485466cc993879ee1')),
        cp(2_100_000, bytes.fromhex('0000000009f961804cd7f43da05f08a94a2fa09f82c7d605afc5982ab242a7e4')),
        cp(2_200_000, bytes.fromhex('0000000002e260b970846a89c23e754a763e7c5f1578b6ec4e67bdb94c667997')),
        cp(2_300_000, bytes.fromhex('0000000006e0894c8f7fd029fe446a42433875647759183ba3fbb0ff0b7ceb64')),
        cp(2_400_000, bytes.fromhex('0000000011ab28f3be17e3a098307fa73750cc8d74f1f60cfb44b524a60c94ec')),
        cp(2_500_000, bytes.fromhex('00000000045d2bcc10c896bfc7d1f28788e3530a81f50ee096f386eec772634f')),
        cp(2_600_000, bytes.fromhex('000000000766b9ac25e2ece5685effa834e61284e38f368c841210606bb1fdfc')),
        cp(2_700_000, bytes.fromhex('0000000005d0ee31d0f47f6ff9aa570b9f25b9d44a8a59cea0e0f8a1729b9c90')),
        cp(2_800_000, bytes.fromhex('000000000a5bd4f266fa13d2c0594cabf6465758f7f5814bde626032706b81e5')),
        cp(2_900_000, bytes.fromhex('000000000b11b0a09ff0d7c2cfd9228f31c53008e700532e439d3a3d9c63fb8e')),
        cp(3_000_000, bytes.fromhex('00000000013289569569cd51580183a2c870dfe5a395adaa00ae66fefe51af3d')),
        cp(3_100_000, bytes.fromhex('00000000170c55e6ec207400bfc42786c1e0c32fe045a1d815f930daf2bf3020')),
        cp(3_200_000, bytes.fromhex('00000000149986cb99c202136bd388fb2a7fcba4bdfd6ac049069ac5e08a587f')),
        cp(3_300_000, bytes.fromhex('000000000e16f87ac7133639cb52a99574944b8457939396e7faf1615fcfdb0f')),
        cp(3_400_000, bytes.fromhex('000000000f551f6224a459904436072f5ff10fd3db17f2d7e25b1ef9b149c121')),
        cp(3_500_000, bytes.fromhex('0000000006572b8cf41130e88776adf8583e970905df2afe593ca31c91ab0c4c')),
        cp(3_600_000, bytes.fromhex('000000000215fcc7018cc31bbfb943ca43c6297529fa008bf34665f3ac64d340')),
        cp(3_700_000, bytes.fromhex('000000000dbf5e8ab4f90f2187db6db429c9d0cb8169051ce8a9e79b810509d7')),
        cp(3_800_000, bytes.fromhex('00000000030411ec36c7f5386a94e147460d86592f85459e0eadd5cd0e3da7b4')),
        cp(3_900_000, bytes.fromhex('000000000bc2c7078a3c59d878196f1491aad45a0df9d312909d85482ac8d714')),
        cp(4_000_000, bytes.fromhex('000000000eba0dae3ec27cf5596ef49731744edebadb9fbae42160b6aa2e2461')),
        cp(4_100_000, bytes.fromhex('00000000052aa77fd8db71d5306257f9fe068c3401d95b17fcedcccfc9b76c82')),
        cp(4_200_000, bytes.fromhex('00000000010a8dae043c84fcb2cef6a2b42a28279b95af20ab5a098acf2a3565')),
        cp(4_300_000, bytes.fromhex('000000000019da781ef75fa5f59c5537d8ed18b64c589c3e036109cfb1d84f7d')),
    ],
    FEATURE_ACTIVATION=FeatureActivationSettings(
        default_threshold=15_120,  # 15120 = 75% of evaluation_interval (20160)
        features={
            Feature.INCREASE_MAX_MERKLE_PATH_LENGTH: Criteria(
                bit=3,
                # N = 3_548_160
                # Expected to be reached around Sunday, 2024-02-04.
                # Right now the best block is 3_521_000 on testnet (2024-01-26).
                start_height=3_548_160,
                timeout_height=3_588_480,  # N + 2 * 20160 (2 weeks after the start)
                minimum_activation_height=0,
                lock_in_on_timeout=False,
                version='0.59.0',
                signal_support_by_default=True,
            ),

            # NOP feature to test Feature Activation for Transactions
            Feature.NOP_FEATURE_1: Criteria(
                bit=0,
                # N = 4_495_680
                # Expected to be reached around Tuesday, 2025-01-06.
                # Right now the best block is 4_489_259 on testnet (2025-01-03).
                start_height=4_495_680,  # N
                timeout_height=4_576_320,  # N + 4 * 20160 (4 weeks after the start)
                minimum_activation_height=0,
                lock_in_on_timeout=False,
                version='0.63.0',
                signal_support_by_default=True,
            )
        }
    )
)
