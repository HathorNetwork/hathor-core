# encoding: utf-8

from multiprocessing import Process, Queue

from hathor.transaction import Block
from hathor.transaction.exceptions import HathorError

import datetime
import requests
import time
import base64
import argparse
import sys
import signal
from json.decoder import JSONDecodeError

_SLEEP_ON_ERROR_SECONDS = 5


def signal_handler(sig, frame):
    sys.exit(0)


def worker(q_in, q_out):
    signal.signal(signal.SIGINT, signal_handler)
    block, start, end, sleep_seconds = q_in.get()
    block.start_mining(start, end, sleep_seconds=sleep_seconds)
    q_out.put(block.nonce)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('--sleep', type=float, help='Sleep every 2 seconds (in seconds)')
    args = parser.parse_args()

    print('Hathor CPU Miner v1.0.0')
    print('URL: {}'.format(args.url))

    signal.signal(signal.SIGINT, signal_handler)

    sleep_seconds = 0
    if args.sleep:
        sleep_seconds = args.sleep

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
        print('Mining block with weight {}'.format(block.weight))

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
                datetime.datetime.now(),
                block.hash.hex(),
                block.nonce,
                block.weight,
                block.height
            ))
            print('')

            requests.post(args.url, json={'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})
