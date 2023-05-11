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

from typing import Dict, List, Optional, Union

from pydantic import validator

from hathor.checkpoint import Checkpoint
from hathor.utils import pydantic


class HathorSettings(pydantic.BaseModel):
    # Version byte of the address in P2PKH
    P2PKH_VERSION_BYTE: bytes

    # Version byte of the address in MultiSig
    MULTISIG_VERSION_BYTE: bytes

    # Name of the network: "mainnet", "testnet-alpha", "testnet-bravo", ...
    NETWORK_NAME: str

    # Initial bootstrap servers
    BOOTSTRAP_DNS: List[str] = []

    # enable peer whitelist
    ENABLE_PEER_WHITELIST: bool = False

    # To disable reward halving, just set this to `None` and make sure that INITIAL_TOKEN_UNITS_PER_BLOCK is equal to
    # MINIMUM_TOKEN_UNITS_PER_BLOCK.
    BLOCKS_PER_HALVING: Optional[int] = 2 * 60 * 24 * 365  # 1051200, every 365 days

    # Genesis pre-mined outputs
    # P2PKH HMcJymyctyhnWsWTXqhP9txDwgNZaMWf42
    #
    # To generate a new P2PKH script, run:
    # >>> from hathor.transaction.scripts import P2PKH
    # >>> import base58
    # >>> address = base58.b58decode('HMcJymyctyhnWsWTXqhP9txDwgNZaMWf42')
    # >>> P2PKH.create_output_script(address=address).hex()
    GENESIS_OUTPUT_SCRIPT: bytes = bytes.fromhex('76a914a584cf48b161e4a49223ed220df30037ab740e0088ac')

    # Genesis timestamps, nonces and hashes
    GENESIS_TIMESTAMP: int = 1572636343  # used as is for genesis_block, +1 for genesis_tx1 and +2 for genesis_tx2
    GENESIS_BLOCK_NONCE: int = 3526202
    GENESIS_BLOCK_HASH: bytes = bytes.fromhex('000007eb968a6cdf0499e2d033faf1e163e0dc9cf41876acad4d421836972038')
    GENESIS_TX1_NONCE: int = 12595
    GENESIS_TX1_HASH: bytes = bytes.fromhex('00025d75e44804a6a6a099f4320471c864b38d37b79b496ee26080a2a1fd5b7b')
    GENESIS_TX2_NONCE: int = 21301
    GENESIS_TX2_HASH: bytes = bytes.fromhex('0002c187ab30d4f61c11a5dc43240bdf92dba4d19f40f1e883b0a5fdac54ef53')

    # Weight of genesis and minimum weight of a tx/block
    MIN_BLOCK_WEIGHT: int = 21
    MIN_TX_WEIGHT: int = 14
    MIN_SHARE_WEIGHT: int = 21

    # Number of blocks to be found with the same hash algorithm as `block`.
    # The bigger it is, the smaller the variance of the hash rate estimator is.
    BLOCK_DIFFICULTY_N_BLOCKS: int = 134

    # Maximum difference between the weight and the min_weight.
    MAX_TX_WEIGHT_DIFF: float = 4.0
    MAX_TX_WEIGHT_DIFF_ACTIVATION: float = 32.0

    # After how many blocks can a reward be spent
    REWARD_SPEND_MIN_BLOCKS: int = 300

    # Multiplier coefficient to adjust the minimum weight of a normal tx to 18
    MIN_TX_WEIGHT_COEFFICIENT: float = 1.6

    # Amount in which tx min weight reaches the middle point between the minimum and maximum weight
    MIN_TX_WEIGHT_K: int = 100

    # Where to download whitelist from
    WHITELIST_URL: Optional[str] = None

    # Block checkpoints
    CHECKPOINTS: List[Checkpoint] = []

    # Used on testing to enable slow asserts that help catch bugs but we don't want to run in production
    SLOW_ASSERTS: bool = False

    # List of soft voided transaction.
    SOFT_VOIDED_TX_IDS: List[bytes] = []

    @validator('CHECKPOINTS', pre=True)
    def _parse_checkpoints(cls, checkpoints: Union[Dict[int, str], List[Checkpoint]]) -> List[Checkpoint]:
        if isinstance(checkpoints, Dict):
            return [
                Checkpoint(height, bytes.fromhex(_hash))
                for height, _hash in checkpoints.items()
            ]

        if not isinstance(checkpoints, List):
            raise TypeError(f'expected \'Dict[int, str]\' or \'List[Checkpoint]\', got {checkpoints}')

        return checkpoints

    _parse_hex_str = validator(
        'P2PKH_VERSION_BYTE',
        'MULTISIG_VERSION_BYTE',
        'GENESIS_OUTPUT_SCRIPT',
        'GENESIS_BLOCK_HASH',
        'GENESIS_TX1_HASH',
        'GENESIS_TX2_HASH',
        pre=True,
        allow_reuse=True
    )(pydantic.parse_hex_str)

    _parse_soft_voided_tx_id = validator(
        'SOFT_VOIDED_TX_IDS',
        pre=True,
        each_item=True,
        allow_reuse=True
    )(pydantic.parse_hex_str)
