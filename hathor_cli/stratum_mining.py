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

import sys
from argparse import ArgumentParser, Namespace

from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--address', help='Address to send funds to', type=str, required=False)
    parser.add_argument('--host', help='Hostname of Stratum server', type=str, required=True)
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--nproc', help='Number of mining processes', type=int)
    return parser


def execute(args: Namespace) -> None:
    from hathor.crypto.util import decode_address
    from hathor.reactor import initialize_global_reactor
    from hathor.stratum import StratumClient
    from hathor.wallet.exceptions import InvalidAddress

    address = None
    if args.address is not None:
        try:
            decode_address(args.address)
            address = args.address
        except InvalidAddress:
            print('The given address is invalid')
            sys.exit(-1)

    reactor = initialize_global_reactor()
    miner = StratumClient(proc_count=args.nproc, address=address, reactor=reactor)
    miner.start()
    point = TCP4ClientEndpoint(reactor, args.host, args.port)
    connectProtocol(point, miner)
    reactor.run()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
