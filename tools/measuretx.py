# encoding: utf-8

import json
import requests
import time
import argparse
import random
import signal
import sys
from json.decoder import JSONDecodeError

_SLEEP_ON_ERROR_SECONDS = 5


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('addresses', nargs='*')
    parser.add_argument('--interval', type=float, help='Interval')
    args = parser.parse_args()

    import urllib.parse
    send_tokens_url = urllib.parse.urljoin(args.url, '/wallet/send_tokens/')

    print('Hathor TX Sender v1.0.0')
    print('URL: {}'.format(args.url))
    print('Send tokens URL: {}'.format(send_tokens_url))

    #unlock_wallet_url = urllib.parse.urljoin(args.url, '/wallet/unlock/')
    #response = requests.post(unlock_wallet_url, data={'passphrase': 'abc'})
    #print(response.text)
    #print('Wallet successfully unlocked')
    #print('')

    profiler_url = urllib.parse.urljoin(args.url, '/profiler/')
    response = requests.post(profiler_url + '?start')
    print(response.text)

    t0 = time.time()
    count = 0

    if not args.addresses:
        print('Error. You must give at least one address.')

    def signal_handler(sig, frame):
        response = requests.post(profiler_url + '?stop')
        print(response.text)
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        address = random.choice(args.addresses)
        value = random.randint(10, 100)
        #print('Sending {} tokens to {}...'.format(address, value))

        data = {
            'outputs': [{'address': address, 'value': value}],
            'inputs': []
        }
        response = requests.post(send_tokens_url, json={'data': data})
        try:
            data = response.json()
            assert data['success']
        except (AssertionError, JSONDecodeError) as e:
            print('Error reading response from server: %s' % response)
            print(response.text)
            print(e)
            print('Waiting %d seconds to try again...' % _SLEEP_ON_ERROR_SECONDS)
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
        else:
            #print('Response:', data)
            if args.interval:
                time.sleep(args.interval)
            count += 1
            t1 = time.time()
            if t1 - t0 > 5:
                print('')
                print('  {} tx/s'.format(count / (t1 - t0)))
                print('')
                count = 0
                t0 = t1

