import sys
from argparse import ArgumentParser, Namespace

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--address', help='Address to send funds to', type=str, required=False)
    parser.add_argument('--host', help='Hostname of Stratum server', type=str, required=True)
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--nproc', help='Number of mining processes', type=int)
    return parser


def execute(args: Namespace) -> None:
    from hathor.crypto.util import decode_address
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

    miner = StratumClient(proc_count=args.nproc, address=address)
    miner.start()
    point = TCP4ClientEndpoint(reactor, args.host, args.port)
    connectProtocol(point, miner)
    reactor.run()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
