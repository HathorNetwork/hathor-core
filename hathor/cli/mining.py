import base64
import datetime
import math
import signal
import sys
import time
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from json.decoder import JSONDecodeError
from multiprocessing import Process, Queue
from typing import Tuple

import requests

_SLEEP_ON_ERROR_SECONDS = 5
_MAX_CONN_RETRIES = math.inf


def signal_handler(sig, frame):
    sys.exit(0)


def worker(q_in, q_out):
    signal.signal(signal.SIGINT, signal_handler)
    block, start, end, sleep_seconds = q_in.get()
    block.start_mining(start, end, sleep_seconds=sleep_seconds)
    q_out.put(block)


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('hash_algorithm', help='sha256d or scrypt')
    parser.add_argument('--init-delay', type=float, help='Wait N seconds before starting (in seconds)', default=None)
    parser.add_argument('--sleep', type=float, help='Sleep every 2 seconds (in seconds)')
    parser.add_argument('--count', type=int, help='Quantity of blocks to be mined')
    return parser


def execute(args: Namespace) -> None:
    from requests.exceptions import ConnectionError

    from hathor.transaction import Block
    from hathor.transaction.exceptions import HathorError

    print('Hathor CPU Miner v1.0.0')
    print('URL: {}'.format(args.url))

    if args.init_delay:
        print('Init delay {} seconds'.format(args.init_delay))
        time.sleep(args.init_delay)

    signal.signal(signal.SIGINT, signal_handler)

    hash_algorithm = args.hash_algorithm
    if hash_algorithm not in ('sha256d', 'scrypt'):
        raise ArgumentTypeError('Invalid hash algorithm')

    sleep_seconds = 0
    if args.sleep:
        sleep_seconds = args.sleep

    total = 0
    conn_retries = 0
    q_in: Queue[Tuple[Block, int, int, int]]
    q_out: Queue[Block]
    q_in, q_out = Queue(), Queue()
    while True:
        print('Requesting mining information...')
        try:
            response = requests.get(args.url, params={'hash_algorithm': hash_algorithm})
        except ConnectionError as e:
            print('Error connecting to server: {}'.format(args.url))
            print(e)
            if conn_retries >= _MAX_CONN_RETRIES:
                print('Too many connection failures, giving up.')
                sys.exit(1)
            else:
                conn_retries += 1
                print('Waiting %d seconds to try again ({} of {})...'.format(_SLEEP_ON_ERROR_SECONDS, conn_retries,
                                                                             _MAX_CONN_RETRIES))
                time.sleep(_SLEEP_ON_ERROR_SECONDS)
                continue
        else:
            conn_retries = 0
        try:
            data = response.json()
        except JSONDecodeError as e:
            print('Error reading response from server: {}'.format(response))
            print(e)
            print('Waiting {} seconds to try again...'.format(_SLEEP_ON_ERROR_SECONDS))
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
            continue
        block_bytes = base64.b64decode(data['block_bytes'])
        block = Block.create_from_struct(block_bytes)
        assert block.hash is not None
        assert isinstance(block, Block)
        print('Mining block with weight {}'.format(block.weight))

        p = Process(target=worker, args=(q_in, q_out))
        p.start()
        q_in.put((block, 0, 2**32, sleep_seconds))
        p.join()

        block = q_out.get()
        block.update_hash()
        assert block.hash is not None
        print('[{}] New block found: {} (nonce={}, weight={})'.format(datetime.datetime.now(), block.hash.hex(),
                                                                      block.nonce, block.weight))

        try:
            block.verify_without_storage()
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
