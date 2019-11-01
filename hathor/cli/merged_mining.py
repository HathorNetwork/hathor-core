from argparse import ArgumentParser, Namespace

from twisted.internet import reactor


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--hathor-stratum', help='Endpoint of the Hathor Stratum', type=str, required=True)
    parser.add_argument('--hathor-address', help='Hathor address to send funds to', type=str, required=False)
    parser.add_argument('--bitcoin-rpc', help='Endpoint of the Bitcoin RPC', type=str, required=True)
    parser.add_argument('--bitcoin-address', help='Bitcoin address to send funds to', type=str, required=False)
    return parser


def execute(args: Namespace) -> None:
    from hathor.merged_mining import MergedMiningCoordinator
    from hathor.merged_mining.bitcoin_rpc import BitcoinRPC

    bitcoin_rpc = BitcoinRPC(reactor, args.bitcoin_rpc)

    # TODO: validate addresses?
    merged_mining = MergedMiningCoordinator(
        port=args.port, bitcoin_rpc=bitcoin_rpc, hathor_stratum=args.hathor_stratum,
        payback_address_hathor=args.hathor_address, payback_address_bitcoin=args.bitcoin_address,
    )
    merged_mining.start()
    reactor.run()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
