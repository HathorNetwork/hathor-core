import sys
from argparse import ArgumentParser, Namespace

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.logger import FileLogObserver, FilteringLogObserver, LogLevel, LogLevelFilterPredicate, globalLogPublisher

from hathor.cli.run_node import formatLogEvent
from hathor.crypto.util import decode_address
from hathor.stratum import StratumClient
from hathor.wallet.exceptions import InvalidAddress


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--address', help='Address to send funds to', type=str, required=False)
    parser.add_argument('--host', help='Hostname of Stratum server', type=str, required=True)
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--nproc', help='Number of mining processes', type=int)
    return parser


def execute(args: Namespace) -> None:
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
    loglevel_filter = LogLevelFilterPredicate(LogLevel.info)
    loglevel_filter.setLogLevelForNamespace('hathor.stratum', LogLevel.debug)
    loglevel_filter.setLogLevelForNamespace('twisted.python.log', LogLevel.warn)
    observer = FilteringLogObserver(
        FileLogObserver(sys.stdout, formatLogEvent),
        [loglevel_filter],
    )
    globalLogPublisher.addObserver(observer)

    parser = create_parser()
    args = parser.parse_args()
    execute(args)
