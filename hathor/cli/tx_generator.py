import random
import signal
import sys
import time
from argparse import ArgumentParser
from json.decoder import JSONDecodeError

import requests

_SLEEP_ON_ERROR_SECONDS = 5


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('--address', action='append')
    parser.add_argument('--value', action='append')
    parser.add_argument('--rate', type=float, help='tx/s')
    parser.add_argument('--weight', type=float, help='Weight')
    parser.add_argument('--count', type=int, help='Quantity of txs to be generated')
    parser.add_argument('--profiler', action='store_true', default=False, help='Enable profiling')
    return parser


def execute(args):
    import urllib.parse
    send_tokens_url = urllib.parse.urljoin(args.url, '/wallet/send_tokens/')

    print('Hathor TX Sender v1.0.0')
    print('URL: {}'.format(args.url))
    print('Send tokens URL: {}'.format(send_tokens_url))
    print('Rate: {} tx/s'.format(args.rate))

    latest_timestamp = 0

    if args.rate:
        interval = 1. / args.rate
    else:
        interval = None

    if args.address:
        addresses = args.address
    else:
        address_url = urllib.parse.urljoin(args.url, '/wallet/address')
        response = requests.get(address_url + '?new=false')
        addresses = [response.json()['address']]

    print('Addresses: {}'.format(addresses))

    def signal_handler(sig, frame):
        if args.profiler:
            response = requests.post(profiler_url, json={'stop': True})
            print(response.text)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if args.profiler:
        profiler_url = urllib.parse.urljoin(args.url, '/profiler/')
        response = requests.post(profiler_url, json={'start': True})
        print(response.text)

    t0 = time.time()
    total = 0
    count = 0
    while True:
        address = random.choice(addresses)
        if args.value:
            value = random.choice(args.value)
        else:
            value = random.randint(10, 100)
        # print('Sending {} tokens to {}...'.format(address, value))

        data = {'outputs': [{'address': address, 'value': value}], 'inputs': []}
        if args.weight:
            data['weight'] = args.weight
        response = requests.post(send_tokens_url, json={'data': data})
        try:
            data = response.json()
            assert data['success']
            total += 1
            if args.count and total == args.count:
                break
            latest_timestamp = data['tx']['timestamp']
        except (AssertionError, JSONDecodeError) as e:
            print('Error reading response from server: %s' % response)
            print(response.text)
            print(e)
            print('Waiting %d seconds to try again...' % _SLEEP_ON_ERROR_SECONDS)
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
        else:
            # print('Response:', data)
            if interval:
                time.sleep(interval)
            count += 1
            t1 = time.time()
            if t1 - t0 > 5:
                measure = count / (t1 - t0)
                if interval:
                    error = 1. / measure - 1. / args.rate
                    assert interval > error, 'interval={} error={}'.format(interval, error)
                    interval -= error
                print('')
                print('  {} tx/s (latest timestamp={})'.format(measure, latest_timestamp))
                print('')
                count = 0
                t0 = t1


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
