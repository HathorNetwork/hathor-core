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

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x28',
    MULTISIG_VERSION_BYTE=b'\x64',
    NETWORK_NAME='mainnet',
    BOOTSTRAP_DNS=['mainnet.hathor.network'],
    ENABLE_PEER_WHITELIST=True,
    WHITELIST_URL='https://hathor-public-files.s3.amazonaws.com/whitelist_peer_ids',
    # Genesis stuff
    # output addr: HJB2yxxsHtudGGy3jmVeadwMfRi2zNCKKD
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a9147fd4ae0e4fb2d2854e76d359029d8078bb99649e88ac'),
    GENESIS_TIMESTAMP=1578075305,
    GENESIS_BLOCK_NONCE=2591358,
    GENESIS_BLOCK_HASH=bytes.fromhex('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc'),
    GENESIS_TX1_NONCE=7715,
    GENESIS_TX1_HASH=bytes.fromhex('0002d4d2a15def7604688e1878ab681142a7b155cbe52a6b4e031250ae96db0a'),
    GENESIS_TX2_NONCE=3769,
    GENESIS_TX2_HASH=bytes.fromhex('0002ad8d1519daaddc8e1a37b14aac0b045129c01832281fb1c02d873c7abbf9'),
    CHECKPOINTS=[
        cp(100_000, bytes.fromhex('0000000000001247073138556b4f60fff3ff6eec6521373ccee5a6526a7c10af')),
        cp(200_000, bytes.fromhex('00000000000001bf13197340ae0807df2c16f4959da6054af822550d7b20e19e')),
        cp(300_000, bytes.fromhex('00000000000000e1e8bdba2006cc34db3a1f20294cbe87bd52cceda245238290')),
        cp(400_000, bytes.fromhex('000000000000002ae98f2a15db331d059eeed34d71f813f51d1ac1dbf3d94089')),
        cp(500_000, bytes.fromhex('00000000000000036f2f7234f7bf83b5746ce9b8179922d2781efd82aa3d72bf')),
        cp(600_000, bytes.fromhex('0000000000000001ad38d502f537ce757d7e732230d22434238ca215dd92cca1')),
        cp(700_000, bytes.fromhex('000000000000000066f04be2f3a8607c1c71682e65e07150822fb03afcbf4035')),
        cp(800_000, bytes.fromhex('0000000000000000958372b3ce24a26ce97a3b063c835e7d55c632f289f2cdb0')),
        cp(900_000, bytes.fromhex('0000000000000000c9bac3c3c71a1324f66481be03ad0e5d5fbbed94fc6b8794')),
        cp(1_000_000, bytes.fromhex('00000000000000001060adafe703b8aa28c7d2cfcbddf77d52e62ea0a1df5416')),
        cp(1_100_000, bytes.fromhex('00000000000000000ecc349992158a3972e7a24af494a891a8d1ae3ab982ee4e')),
        cp(1_200_000, bytes.fromhex('000000000000000091ddabd35a0c3984609e2892b72b14d38d23d58e1fa87c91')),
        cp(1_300_000, bytes.fromhex('00000000000000000244794568649ac43e0abd4b53b1a583b6cc8e243e65f582')),
        cp(1_400_000, bytes.fromhex('000000000000000011a65b1c3cba2b94ad05525ac2ec60f315bb7b204c8160c7')),
    ]
)
