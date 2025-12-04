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
    parser.add_argument('partial_tx', type=str, help='Tx to be signed in hex')
    parser.add_argument('private_key', type=str, help='Encrypted private key in hex')
    return parser


def execute(args: Namespace, priv_key_password: str) -> None:
    from hathor.transaction import Transaction
    from hathor.wallet.util import generate_signature

    tx = Transaction.create_from_struct(bytes.fromhex(args.partial_tx))
    assert isinstance(tx, Transaction)

    signature = generate_signature(tx, bytes.fromhex(args.private_key), password=priv_key_password.encode())
    print('Signature: ', signature.hex())


def main():
    parser = create_parser()
    args = parser.parse_args()
    priv_key_password = getpass.getpass(prompt='Password to decrypt the private key:')
    execute(args, priv_key_password)
