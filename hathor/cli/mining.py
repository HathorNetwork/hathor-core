import argparse
import base64
import datetime
import signal
import sys
import time
from argparse import ArgumentParser, Namespace
from json.decoder import JSONDecodeError
from multiprocessing import Process, Queue
from typing import Tuple

import requests

_SLEEP_ON_ERROR_SECONDS = 5


def signal_handler(sig, frame):
    sys.exit(0)


def worker(q_in, q_out):
    signal.signal(signal.SIGINT, signal_handler)
    block, start, end, sleep_seconds = q_in.get()
    block.start_mining(start, end, sleep_seconds=sleep_seconds)
    q_out.put(block.nonce)


def create_parser() -> ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('--sleep', type=float, help='Sleep every 2 seconds (in seconds)')
    parser.add_argument('--count', type=int, help='Quantity of blocks to be mined')
    return parser


def execute(args: Namespace) -> None:
    from hathor.transaction import Block
    from hathor.transaction.exceptions import HathorError

    print('Hathor CPU Miner v1.0.0')
    print('URL: {}'.format(args.url))

    signal.signal(signal.SIGINT, signal_handler)

    sleep_seconds = 0
    if args.sleep:
        sleep_seconds = args.sleep

    total = 0
    while True:
        print('Requesting mining information...')
        response = requests.get(args.url)
        try:
            data = response.json()
        except JSONDecodeError as e:
            print('Error reading response from server: %s' % response)
            print(e)
            print('Waiting %d seconds to try again...' % _SLEEP_ON_ERROR_SECONDS)
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
            continue
        block_bytes = base64.b64decode(data['block_bytes'])
        block = Block.create_from_struct(block_bytes)
        assert block.hash is not None
        assert isinstance(block, Block)
        print('Mining block with weight {}'.format(block.weight))

        q_in: Queue[Tuple[Block, int, int, int]]
        q_out: Queue[int]
        q_in, q_out = Queue(), Queue()
        p = Process(target=worker, args=(q_in, q_out))
        p.start()
        q_in.put((block, 0, 2**32, sleep_seconds))
        p.join()

        block.nonce = q_out.get()
        block.update_hash()
        try:
            block.verify_without_storage()
        except HathorError:
            pass
        else:
            block_bytes = block.get_struct()

            print('[{}] New block found: {} (nonce={}, weight={}, height={})'.format(
                datetime.datetime.now(), block.hash.hex(), block.nonce, block.weight, block.height))
            print('')

            requests.post(args.url, json={'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})

        total += 1
        if args.count and total == args.count:
            break


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
