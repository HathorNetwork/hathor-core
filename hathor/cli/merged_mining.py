import asyncio
from argparse import ArgumentParser, Namespace

from structlog import get_logger

logger = get_logger()


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--hathor-api', help='Endpoint of the Hathor API (without version)', type=str, required=True)
    parser.add_argument('--hathor-address', help='Hathor address to send funds to', type=str, required=False)
    parser.add_argument('--bitcoin-rpc', help='Endpoint of the Bitcoin RPC', type=str, required=True)
    parser.add_argument('--bitcoin-address', help='Bitcoin address to send funds to', type=str, required=False)
    parser.add_argument('--min-diff', help='Minimum difficulty to set for jobs', type=int, required=False)
    return parser


def execute(args: Namespace) -> None:
    from hathor.client import HathorClient
    from hathor.merged_mining import MergedMiningCoordinator
    from hathor.merged_mining.bitcoin_rpc import BitcoinRPC

    loop = asyncio.get_event_loop()

    bitcoin_rpc = BitcoinRPC(args.bitcoin_rpc)
    hathor_client = HathorClient(args.hathor_api)
    # TODO: validate addresses?
    merged_mining = MergedMiningCoordinator(
        bitcoin_rpc=bitcoin_rpc,
        hathor_client=hathor_client,
        payback_address_hathor=args.hathor_address,
        payback_address_bitcoin=args.bitcoin_address,
        address_from_login=not (args.hathor_address and args.bitcoin_address),
        min_difficulty=args.min_diff,
    )
    loop.run_until_complete(bitcoin_rpc.start())
    loop.run_until_complete(hathor_client.start())
    loop.run_until_complete(merged_mining.start())

    server = loop.run_until_complete(loop.create_server(merged_mining, '0.0.0.0', args.port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info('Stopping')
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.run_until_complete(merged_mining.stop())
    loop.run_until_complete(hathor_client.stop())
    loop.run_until_complete(bitcoin_rpc.stop())
    loop.close()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
