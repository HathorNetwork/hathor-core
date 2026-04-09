# Copyright 2024 Hathor Labs
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

import sys

from hathor.utils.pydantic import BaseModel  # skip-cli-import-custom-check


class GenerateGenesisArgs(BaseModel):
    tokens: int
    address: str
    block_timestamp: int
    min_block_weight: int
    min_tx_weight: int


def main() -> None:
    from hathor_cli.util import create_parser
    from hathor.transaction.genesis import generate_new_genesis

    parser = create_parser()
    parser.add_argument('--tokens', type=int, help='Amount of genesis tokens, including decimals', required=True)
    parser.add_argument('--address', type=str, help='Address for genesis tokens', required=True)
    parser.add_argument('--block-timestamp', type=int, help='Timestamp for the genesis block', required=True)
    parser.add_argument('--min-block-weight', type=float, help='The MIN_BLOCK_WEIGHT', required=True)
    parser.add_argument('--min-tx-weight', type=float, help='The MIN_TX_WEIGHT', required=True)

    raw_args = parser.parse_args(sys.argv[1:])
    args = GenerateGenesisArgs.model_validate((vars(raw_args)))

    block, tx1, tx2 = generate_new_genesis(
        tokens=args.tokens,
        address=args.address,
        block_timestamp=args.block_timestamp,
        min_block_weight=args.min_block_weight,
        min_tx_weight=args.min_tx_weight,
    )

    print('# Paste this output into your network\'s yaml configuration file')
    print()
    print('GENESIS_BLOCK_HASH:', block.hash_hex)
    print('GENESIS_TX1_HASH:', tx1.hash_hex)
    print('GENESIS_TX2_HASH:', tx2.hash_hex)
    print()
    print('GENESIS_OUTPUT_SCRIPT:', block.outputs[0].script.hex())
    print('GENESIS_BLOCK_TIMESTAMP:', block.timestamp)
    print('GENESIS_BLOCK_NONCE:', block.nonce)
    print('GENESIS_TX1_NONCE:', tx1.nonce)
    print('GENESIS_TX2_NONCE:', tx2.nonce)
    print()
    print('MIN_BLOCK_WEIGHT:', args.min_block_weight)
    print('MIN_TX_WEIGHT:', args.min_tx_weight)
