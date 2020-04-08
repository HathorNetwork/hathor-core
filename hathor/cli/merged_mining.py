from argparse import ArgumentParser, Namespace

from twisted.internet import reactor


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--hathor-api', help='Endpoint of the Hathor API (without version)', type=str, required=True)
    parser.add_argument('--hathor-address', help='Hathor address to send funds to', type=str, required=False)
    parser.add_argument('--bitcoin-rpc', help='Endpoint of the Bitcoin RPC', type=str, required=True)
    parser.add_argument('--bitcoin-address', help='Bitcoin address to send funds to', type=str, required=False)
    return parser


def execute(args: Namespace) -> None:
    from hathor.client import HathorClient
    from hathor.merged_mining import MergedMiningCoordinator
    from hathor.merged_mining.bitcoin_rpc import BitcoinRPC

    bitcoin_rpc = BitcoinRPC(reactor, args.bitcoin_rpc)
    hathor_client = HathorClient(args.hathor_api)

    # TODO: validate addresses?
    merged_mining = MergedMiningCoordinator(
        port=args.port, bitcoin_rpc=bitcoin_rpc, hathor_client=hathor_client,
        payback_address_hathor=args.hathor_address, payback_address_bitcoin=args.bitcoin_address,
    )
    merged_mining.start()
    reactor.run()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
