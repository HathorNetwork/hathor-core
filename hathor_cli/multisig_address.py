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

from cryptography.hazmat.primitives import serialization


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()
    parser.add_argument('signatures_required', type=int, help='Mimimum quantity of signatures required')
    parser.add_argument('--pubkey_count', type=int, help='Quantity of public keys in the multisig')
    parser.add_argument('--public_keys', type=str, help='Public keys in hex separated by comma')
    parser.add_argument('--dir', type=str, help='Directory of key pair wallet keys')
    return parser


def execute(args: Namespace, wallet_passwd: str) -> None:
    from hathor.crypto.util import get_private_key_bytes, get_public_key_bytes_compressed
    from hathor.wallet import Wallet
    from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script

    if (args.pubkey_count and args.pubkey_count > 16) or args.signatures_required > 16:
        print('Error: maximum number of public keys or signatures required is 16')
        return

    if not args.pubkey_count and not args.public_keys:
        print('Error: you must give at least pubkey_count or public_keys')
        return

    if args.dir:
        wallet = Wallet(directory=args.dir)
    else:
        wallet = Wallet()

    wallet.unlock(wallet_passwd.encode())

    if args.public_keys:
        public_keys_hex = args.public_keys.split(',')
        public_bytes = [bytes.fromhex(pkh) for pkh in public_keys_hex]
    else:
        # If not public keys as parameter, we need to create them
        public_bytes = []

        for i in range(args.pubkey_count):
            addr = wallet.get_unused_address()
            key = wallet.keys[addr]
            pk = key.get_private_key(wallet_passwd.encode())
            public_key_bytes = get_public_key_bytes_compressed(pk.public_key())
            public_bytes.append(public_key_bytes)
            print('------------------\n')
            print('Key {}\n'.format(i + 1))
            print('Private key: {}\n'.format(
                get_private_key_bytes(
                    pk, encryption_algorithm=serialization.BestAvailableEncryption(wallet_passwd.encode())).hex()))
            print('Public key: {}\n'.format(public_key_bytes.hex()))
            print('Address: {}\n'.format(addr))

    # Then we create the redeem script
    redeem_script = generate_multisig_redeem_script(args.signatures_required, public_bytes)

    print('------------------\n')
    print('Redeem script:', redeem_script.hex())
    print('\n')

    # Then we created the multisig address
    address = generate_multisig_address(redeem_script)

    print('------------------\n')
    print('MultiSig address:', address)
    print('------------------\n\n')


def main():
    parser = create_parser()
    args = parser.parse_args()
    wallet_passwd = getpass.getpass(prompt='Wallet password:')
    execute(args, wallet_passwd)
