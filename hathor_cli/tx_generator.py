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

import math
import random
import signal
import sys
import time
from argparse import ArgumentParser, Namespace
from json.decoder import JSONDecodeError
from typing import Any

import requests

_SLEEP_ON_ERROR_SECONDS = 5
_MAX_CONN_RETRIES = math.inf


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('--address', action='append')
    parser.add_argument('--value', action='append')
    parser.add_argument('--rate', type=float, help='tx/s')
    parser.add_argument('--weight', type=float, help='Weight')
    parser.add_argument('--count', type=int, help='Quantity of txs to be generated')
    parser.add_argument('--timestamp', action='append', choices=['client', 'server'], help='If the tx timestamp '
                        'should be set on the client or server. If this parameter is not given, server will set '
                        'the timestamp as part of regular tx creation')
    parser.add_argument('--profiler', action='store_true', default=False, help='Enable profiling')
    return parser


def execute(args: Namespace) -> None:
    import urllib.parse

    from requests.exceptions import ConnectionError

    send_tokens_url = urllib.parse.urljoin(args.url, 'wallet/send_tokens/')

    print('Hathor TX Sender v1.0.0')
    print('URL: {}'.format(args.url))
    print('Send tokens URL: {}'.format(send_tokens_url))
    print('Rate: {} tx/s'.format(args.rate))

    latest_timestamp = 0
    latest_weight = 0
    conn_retries = 0

    if args.rate:
        interval = 1. / args.rate
    else:
        interval = None

    if args.address:
        addresses = args.address
    else:
        address_url = urllib.parse.urljoin(args.url, 'wallet/address') + '?new=false'
        response = None
        while True:
            try:
                response = requests.get(address_url)
                break
            except ConnectionError as e:
                print('Error connecting to server: {}'.format(address_url))
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
        assert response is not None
        addresses = [response.json()['address']]

    print('Addresses: {}'.format(addresses))

    def signal_handler(sig, frame):
        if args.profiler:
            response = requests.post(profiler_url, json={'stop': True})
            print(response.text)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if args.profiler:
        profiler_url = urllib.parse.urljoin(args.url, 'profiler/')
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

        data: dict[str, Any] = {'outputs': [{'address': address, 'value': value}], 'inputs': []}

        if args.timestamp:
            if args.timestamp == 'server':
                data['timestamp'] = 0
            elif args.timestamp == 'client':
                data['timestamp'] = int(time.time())

        if args.weight:
            data['weight'] = args.weight
        try:
            response = requests.post(send_tokens_url, json={'data': data})
        except ConnectionError as e:
            print('Error connecting to server: {}'.format(send_tokens_url))
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
        try:
            data = response.json()
            assert data['success']
            total += 1
            if args.count and total == args.count:
                break
            latest_timestamp = data['tx']['timestamp']
            latest_weight = data['tx']['weight']
        except (AssertionError, JSONDecodeError) as e:
            print('Error reading response from server: {}'.format(response))
            print(response.text)
            print(e)
            print('Waiting {} seconds to try again...'.format(_SLEEP_ON_ERROR_SECONDS))
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
        else:
            # print('Response:', data)
            if interval:
                time.sleep(interval)
            count += 1
            t1 = time.time()
            if t1 - t0 > 5:
                measure = count / (t1 - t0)
                if interval is not None:
                    error = 1. / measure - 1. / args.rate
                    if interval > error:
                        interval -= error
                    else:
                        interval = 0
                # print('')
                print('  {} tx/s (latest timestamp={}, latest weight={}, sleep interval={})'.format(
                      measure, latest_timestamp, latest_weight, interval))
                # print('')
                count = 0
                t0 = t1


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
