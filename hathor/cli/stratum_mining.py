from argparse import ArgumentParser, Namespace

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol

from hathor.stratum import StratumClient


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--host', help='Hostname of Stratum server', type=str, required=True)
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--nproc', help='Number of mining processes', type=int)
    return parser


def execute(args: Namespace) -> None:
    miner = StratumClient(proc_count=args.nproc)
    miner.start()
    point = TCP4ClientEndpoint(reactor, args.host, args.port)
    connectProtocol(point, miner)
    reactor.run()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
