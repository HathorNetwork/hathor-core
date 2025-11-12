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

import getpass
from argparse import ArgumentParser, Namespace


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()
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
