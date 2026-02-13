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

from argparse import ArgumentParser, Namespace


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()
    parser.add_argument('partial_tx', type=str, help='Tx to spend multisig fund')
    parser.add_argument(
        'signatures', type=str,
        help='Signatures in hex of the private keys in the same order as the public keys (separated by a comma)')
    parser.add_argument('redeem_script', type=str, help='Redeem script in hex')
    return parser


def execute(args: Namespace) -> None:
    from hathor.mining.cpu_mining_service import CpuMiningService
    from hathor.transaction.scripts import MultiSig
    from hathor.transaction.vertex_parser import vertex_deserializer

    tx = vertex_deserializer.deserialize(bytes.fromhex(args.partial_tx))

    signatures = [bytes.fromhex(signature) for signature in args.signatures.split(',')]
    input_data = MultiSig.create_input_data(bytes.fromhex(args.redeem_script), signatures)
    tx.inputs[0].data = input_data

    CpuMiningService().resolve(tx)
    print('Transaction after POW: ', tx.get_struct().hex())


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
