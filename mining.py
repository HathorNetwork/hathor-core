# encoding: utf-8

from multiprocessing import Process, Queue

from hathor.transaction import Block
from hathor.transaction.exceptions import HathorError

import datetime
import requests
import base64
import argparse


def worker(q_in, q_out):
    block, start, end = q_in.get()
    block.mining(start, end, sleep=0)
    q_out.put(block.nonce)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('n', type=int, help='Number of mining processes')
    args = parser.parse_args()

    print('Hathor CPU Miner v1.0.0')
    print('URL: {}'.format(args.url))

    while True:
        print('Requesting mining information...')
        response = requests.get(args.url)
        data = response.json()

        block_bytes = base64.b64decode(data['block_bytes'])
        block = Block.create_from_struct(block_bytes)
        print('Mining block with weight {}'.format(block.weight))

        q_in, q_out = Queue(), Queue()
        p = Process(target=worker, args=(q_in, q_out))
        p.start()
        q_in.put((block, 0, 2**32))
        p.join()

        block.nonce = q_out.get()
        block.update_hash()
        try:
            block.verify()
        except HathorError as e:
            pass
        else:
            block_bytes = block.get_struct()

            print('[{}] New block found: {} (nonce={}, weight={})'.format(
                datetime.datetime.now(),
                block.hash.hex(),
                block.nonce,
                block.weight
            ))
            print('')

            requests.post(args.url, data={'block_bytes': base64.b64encode(block_bytes).decode('utf-8')})
