import argparse
import getpass
from argparse import ArgumentParser, Namespace


def create_parser() -> ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=20, help='Number of keys/addresses (default=20)')
    parser.add_argument('--directory', help='Wallet directory')
    return parser


def execute(args: Namespace, password: str) -> None:
    from hathor.wallet import Wallet

    passwd: bytes = password.encode('utf-8')

    count = args.count
    directory = args.directory or './'
    print('Generating {} keys at {}'.format(count, directory))

    wallet = Wallet(directory=directory)
    wallet.unlock(passwd)
    wallet.generate_keys(count=count)
    wallet._write_keys_to_file()


def main():
    parser = create_parser()
    args = parser.parse_args()
    passwd = getpass.getpass(prompt='Wallet password:')
    execute(args, passwd)
