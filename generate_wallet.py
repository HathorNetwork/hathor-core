# encoding: utf-8

from hathor.wallet import Wallet

import argparse
import getpass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=20, help='Number of keys/addresses (default=20)')
    parser.add_argument('--directory', help='Wallet directory')
    args = parser.parse_args()

    passwd = getpass.getpass(prompt='Wallet password:')

    count = args.count
    directory = args.directory or './'
    print('Generating {} keys at {}'.format(count, directory))

    wallet = Wallet(directory=directory)
    wallet.unlock(passwd)
    wallet.generate_keys(count=count)
    wallet._write_keys_to_file()
