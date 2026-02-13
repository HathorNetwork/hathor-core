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

import base64
import datetime
import math
import signal
import sys
import time
from argparse import ArgumentParser, Namespace
from json.decoder import JSONDecodeError
from multiprocessing import Process, Queue

import requests

_SLEEP_ON_ERROR_SECONDS = 5
_MAX_CONN_RETRIES = math.inf


def signal_handler(sig, frame):
    sys.exit(0)


def worker(q_in, q_out):
    from hathor.mining.cpu_mining_service import CpuMiningService
    signal.signal(signal.SIGINT, signal_handler)
    block, start, end, sleep_seconds = q_in.get()
    CpuMiningService().start_mining(block, start=start, end=end, sleep_seconds=sleep_seconds)
    q_out.put(block)


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('--init-delay', type=float, help='Wait N seconds before starting (in seconds)', default=None)
    parser.add_argument('--sleep', type=float, help='Sleep every 2 seconds (in seconds)')
    parser.add_argument('--count', type=int, help='Quantity of blocks to be mined')
    parser.add_argument('--address', help='Address to mine blocks')
    return parser


def execute(args: Namespace) -> None:
    from requests.exceptions import ConnectionError

    from hathor.transaction import Block
    from hathor.transaction.exceptions import HathorError
    from hathor.transaction.vertex_parser import vertex_deserializer

    print('Hathor CPU Miner v1.0.0')
    print('URL: {}'.format(args.url))

    if args.init_delay:
        print('Init delay {} seconds'.format(args.init_delay))
        time.sleep(args.init_delay)

    signal.signal(signal.SIGINT, signal_handler)

    sleep_seconds = 0
    if args.sleep:
        sleep_seconds = args.sleep

    total = 0
    conn_retries = 0
    q_in: Queue[tuple[Block, int, int, int]]
    q_out: Queue[Block]
    q_in, q_out = Queue(), Queue()
    while True:
        print('Requesting mining information...')
        try:
            params = {}
            if args.address:
                params['address'] = args.address
            response = requests.get(args.url, params=params)
        except ConnectionError as e:
            print('Error connecting to server: {}'.format(args.url))
            print(e)
            if conn_retries >= _MAX_CONN_RETRIES:
                print('Too many connection failures, giving up.')
                sys.exit(1)
            else:
                conn_retries += 1
                print('Waiting {} seconds to try again ({} of {})...'.format(_SLEEP_ON_ERROR_SECONDS, conn_retries,
                                                                             _MAX_CONN_RETRIES))
                time.sleep(_SLEEP_ON_ERROR_SECONDS)
                continue
        else:
            conn_retries = 0

        if response.status_code == 503:
            print('Node still syncing. Waiting {} seconds to try again...'.format(_SLEEP_ON_ERROR_SECONDS))
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
            continue

        try:
            data = response.json()
        except JSONDecodeError as e:
            print('Error reading response from server: {}'.format(response))
            print(e)
            print('Waiting {} seconds to try again...'.format(_SLEEP_ON_ERROR_SECONDS))
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
            continue

        if 'block_bytes' not in data:
            print('Something is wrong in the response.')
            print(data)
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
            continue

        block_bytes = base64.b64decode(data['block_bytes'])
        block = vertex_deserializer.deserialize(block_bytes)
        assert isinstance(block, Block)
        print('Mining block with weight {}'.format(block.weight))

        p = Process(target=worker, args=(q_in, q_out))
        p.start()
        q_in.put((block, 0, 2**32, sleep_seconds))
        p.join()

        block = q_out.get()
        block.update_hash()
        print('[{}] New block found: {} (nonce={}, weight={})'.format(datetime.datetime.now(), block.hash.hex(),
                                                                      block.nonce, block.weight))

        try:
            from unittest.mock import Mock

            from hathor.conf.get_settings import get_global_settings
            from hathor.daa import DifficultyAdjustmentAlgorithm
            from hathor.verification.verification_params import VerificationParams
            from hathor.verification.verification_service import VerificationService
            from hathor.verification.vertex_verifiers import VertexVerifiers
            from hathor.feature_activation.utils import Features
            from hathor.transaction.scripts.opcode import OpcodesVersion
            settings = get_global_settings()
            daa = DifficultyAdjustmentAlgorithm(settings=settings)
            verification_params = VerificationParams(nc_block_root_id=None, features=Features(
                count_checkdatasig_op=True,
                nanocontracts=False,
                fee_tokens=False,
                opcodes_version=OpcodesVersion.V2,
            ))
            verifiers = VertexVerifiers.create_defaults(
                reactor=Mock(),
                settings=settings,
                daa=daa,
                feature_service=Mock(),
                tx_storage=Mock(),
            )
            verification_service = VerificationService(settings=settings, verifiers=verifiers)
            verification_service.verify_without_storage(block, verification_params)
        except HathorError:
            print('[{}] ERROR: Block has not been pushed because it is not valid.'.format(datetime.datetime.now()))
        else:
            block_bytes = block.get_struct()
            response = requests.post(args.url, json={'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})
            if not response.ok:
                print('[{}] ERROR: Block has been rejected. Unknown exception.'.format(datetime.datetime.now()))

            if response.ok and response.text != '1':
                print('[{}] ERROR: Block has been rejected.'.format(datetime.datetime.now()))

        print('')

        total += 1
        if args.count and total == args.count:
            break


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
