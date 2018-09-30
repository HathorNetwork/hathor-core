# encoding: utf-8

import json
import requests
import time
import argparse
import random
from json.decoder import JSONDecodeError

_SLEEP_ON_ERROR_SECONDS = 5


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL to get mining bytes')
    parser.add_argument('addresses', nargs='*')
    parser.add_argument('--interval', type=float, help='Interval', default=3)
    args = parser.parse_args()

    import urllib.parse
    send_tokens_url = urllib.parse.urljoin(args.url, '/wallet/send_tokens/')

    print('Hathor TX Sender v1.0.0')
    print('URL: {}'.format(args.url))
    print('Send tokens URL: {}'.format(send_tokens_url))

    if not args.addresses:
        print('Error. You must give at least one address.')

    while True:
        address = random.choice(args.addresses)
        value = random.randint(10, 100)
        print('Sending {} tokens to {}...'.format(address, value))

        data = {
            'outputs': [{'address': address, 'value': value}],
            'inputs': []
        }
        data_bytes = json.dumps(data).encode('utf-8')
        response = requests.post(send_tokens_url, data={'data': data_bytes})
        try:
            data = response.json()
        except JSONDecodeError as e:
            print('Error reading response from server: %s' % response)
            print(response.text)
            print(e)
            print('Waiting %d seconds to try again...' % _SLEEP_ON_ERROR_SECONDS)
            time.sleep(_SLEEP_ON_ERROR_SECONDS)
        else:
            print('Response:', data)
            time.sleep(args.interval)
