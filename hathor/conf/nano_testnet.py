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
    NETWORK_NAME='nano-testnet-alpha',
    BOOTSTRAP_DNS=['alpha.nano-testnet.hathor.network'],
    # Genesis stuff
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a91478e804bf8aa68332c6c1ada274ac598178b972bf88ac'),
    GENESIS_BLOCK_TIMESTAMP=1677601898,
    GENESIS_BLOCK_NONCE=7881594,
    GENESIS_BLOCK_HASH=bytes.fromhex('000003472f6a17c2199e24c481a4326c217d07376acd9598651f8413c008554d'),
    GENESIS_TX1_NONCE=110,
    GENESIS_TX1_HASH=bytes.fromhex('0008f0e9dbe6e4bbc3a85fce7494fee70011b9c7e72f5276daa2a235355ac013'),
    GENESIS_TX2_NONCE=180,
    GENESIS_TX2_HASH=bytes.fromhex('008d81d9d58a43fd9649f33483d804a4417247b4d4e4e01d64406c4177fee0c2'),
    # tx weight parameters. With these settings, tx weight is always 8
    MIN_TX_WEIGHT_K=0,
    MIN_TX_WEIGHT_COEFFICIENT=0,
    MIN_TX_WEIGHT=8,
    CHECKPOINTS=[],
    ENABLE_NANO_CONTRACTS=True,
    BLUEPRINTS={
        bytes.fromhex('3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595'): 'Bet',
        bytes.fromhex('27db2b0b1a943c2714fb19d190ce87dc0094bba463b26452dd98de21a42e96a0'): 'Dozer_Pool',
    },
)
