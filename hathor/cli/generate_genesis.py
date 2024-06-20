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

import os
import sys

import base58


def main():
    from hathor.cli.util import create_parser
    from hathor.conf.get_settings import get_global_settings
    from hathor.mining.cpu_mining_service import CpuMiningService
    from hathor.transaction import Block, Transaction, TxOutput
    from hathor.transaction.scripts import P2PKH

    parser = create_parser()
    parser.add_argument('--config-yaml', type=str, help='Configuration yaml filepath')
    parser.add_argument('--genesis-address', type=str, help='Address for genesis tokens')
    parser.add_argument('--genesis-block-timestamp', type=int, help='Timestamp for the genesis block')

    args = parser.parse_args(sys.argv[1:])
    if not args.config_yaml:
        raise Exception('`--config-yaml` is required')
    if not args.genesis_address:
        raise Exception('`--genesis-address` is required')
    if not args.genesis_block_timestamp:
        raise Exception('`--genesis-block-timestamp` is required')

    os.environ['HATHOR_CONFIG_YAML'] = args.config_yaml
    settings = get_global_settings()
    output_script = P2PKH.create_output_script(address=base58.b58decode(args.genesis_address))
    block_timestamp = int(args.genesis_block_timestamp)
    mining_service = CpuMiningService()

    block = Block(
        timestamp=block_timestamp,
        weight=settings.MIN_BLOCK_WEIGHT,
        outputs=[
            TxOutput(settings.GENESIS_TOKENS, output_script),
        ],
    )
    mining_service.start_mining(block)
    block.update_hash()

    tx1 = Transaction(
        timestamp=settings.GENESIS_TX1_TIMESTAMP,
        weight=settings.MIN_TX_WEIGHT,
    )
    mining_service.start_mining(tx1)
    tx1.update_hash()

    tx2 = Transaction(
        timestamp=settings.GENESIS_TX2_TIMESTAMP,
        weight=settings.MIN_TX_WEIGHT,
    )
    mining_service.start_mining(tx2)
    tx2.update_hash()

    # The output format is compatible with the yaml config file
    print('GENESIS_OUTPUT_SCRIPT:', output_script.hex())
    print('GENESIS_BLOCK_TIMESTAMP:', block.timestamp)
    print('GENESIS_BLOCK_HASH:', block.hash_hex)
    print('GENESIS_BLOCK_NONCE:', block.nonce)
    print('GENESIS_TX1_HASH:', tx1.hash_hex)
    print('GENESIS_TX1_NONCE:', tx1.nonce)
    print('GENESIS_TX2_HASH:', tx2.hash_hex)
    print('GENESIS_TX2_NONCE:', tx2.nonce)
