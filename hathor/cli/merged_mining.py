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

import asyncio
from argparse import ArgumentParser, Namespace
from typing import Any, Dict, Optional

from aiohttp import web
from structlog import get_logger

logger = get_logger()


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--port', help='Port of Stratum server', type=int, required=True)
    parser.add_argument('--status', help='Port of Status server', type=int, required=False)
    parser.add_argument('--debug-listen', help='Port to listen for Debug API', type=int, required=False)
    parser.add_argument('--hathor-api', help='Endpoint of the Hathor API (without version)', type=str, required=True)
    parser.add_argument('--hathor-address', help='Hathor address to send funds to', type=str, required=False)
    parent_chain = parser.add_mutually_exclusive_group()
    parent_chain.add_argument('--bitcoin-rpc', help='Endpoint of the Bitcoin RPC', type=str, required=False)
    parser.add_argument('--bitcoin-address', help='Bitcoin address to send funds to', type=str, required=False)
    parent_chain.add_argument('--digibyte-rpc', help='Endpoint of the DigiByte RPC', type=str, required=False)
    parser.add_argument('--digibyte-address', help='DigiByte address to send funds to', type=str, required=False)
    parser.add_argument('--min-diff', help='Minimum difficulty to set for jobs', type=int, required=False)
    parser.add_argument('--const-diff', help='Constant difficulty, the initially estimated diff or min diff will not'
                                             'be updated', action='store_true')
    return parser


def execute(args: Namespace) -> None:
    from hathor.client import HathorClient
    from hathor.merged_mining import MergedMiningCoordinator
    from hathor.merged_mining.bitcoin_rpc import BitcoinRPC
    from hathor.merged_mining.debug_api import make_app as make_debug_app
    from hathor.merged_mining.digibyte_rpc import DigibyteRPC
    from hathor.merged_mining.status_api import make_app as make_status_app

    loop = asyncio.get_event_loop()

    kwargs: Dict[str, Any] = {}
    has_parent_address = False
    if args.bitcoin_rpc:
        kwargs['bitcoin_rpc'] = bitcoin_rpc = BitcoinRPC(args.bitcoin_rpc)
        kwargs['payback_address_bitcoin'] = args.bitcoin_address
        has_parent_address = bool(args.bitcoin_address)
        logger.info('start Bitcoin RPC', url=args.bitcoin_rpc)
        loop.run_until_complete(bitcoin_rpc.start())
    elif args.digibyte_rpc:
        kwargs['digibyte_rpc'] = digibyte_rpc = DigibyteRPC(args.digibyte_rpc)
        kwargs['payback_address_digibyte'] = args.digibyte_address
        has_parent_address = bool(args.digibyte_address)
        logger.info('start DigiByte RPC', url=args.digibyte_rpc)
        loop.run_until_complete(digibyte_rpc.start())
    else:
        raise ValueError('should have at least one parent chain')
    hathor_client = HathorClient(args.hathor_api)
    merged_mining = MergedMiningCoordinator(
        hathor_client=hathor_client,
        payback_address_hathor=args.hathor_address,
        address_from_login=not (args.hathor_address and has_parent_address),
        min_difficulty=args.min_diff,
        constant_difficulty=args.const_diff,
        **kwargs,
    )
    logger.info('start Hathor Client', url=args.hathor_api)
    loop.run_until_complete(hathor_client.start())
    logger.info('start Merged Mining Server', listen=f'0.0.0.0:{args.port}')
    loop.run_until_complete(merged_mining.start())
    mm_server = loop.run_until_complete(loop.create_server(merged_mining, '0.0.0.0', args.port))
    web_runner: Optional[web.BaseRunner] = None
    if args.status:
        logger.info('start Status API', listen=f'0.0.0.0:{args.status}')
        app = loop.run_until_complete(make_status_app(merged_mining))
        web_runner = web.AppRunner(app)
        loop.run_until_complete(web_runner.setup())
        site = web.TCPSite(web_runner, '0.0.0.0', args.status)
        loop.run_until_complete(site.start())
    if args.debug_listen:
        logger.info('start DEBUG API', listen=f'127.0.0.1:{args.debug_listen}')
        app = loop.run_until_complete(make_debug_app(merged_mining))
        web_runner = web.AppRunner(app)
        loop.run_until_complete(web_runner.setup())
        site = web.TCPSite(web_runner, '127.0.0.1', args.debug_listen)
        loop.run_until_complete(site.start())
    try:
        logger.info('initialize')
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info('quit')
    mm_server.close()
    if web_runner is not None:
        loop.run_until_complete(web_runner.cleanup())
    loop.run_until_complete(mm_server.wait_closed())
    loop.run_until_complete(merged_mining.stop())
    loop.run_until_complete(hathor_client.stop())
    if args.bitcoin_rpc:
        loop.run_until_complete(bitcoin_rpc.stop())
    elif args.digibyte_rpc:
        loop.run_until_complete(digibyte_rpc.stop())
    loop.close()
    logger.info('bye')


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
