# Copyright 2026 Hathor Labs
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

from __future__ import annotations

import os
from argparse import ArgumentParser, FileType

from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.task import deferLater

logger = get_logger()

def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()

    parser.add_argument(
        '--dump-to',
        type=FileType('w', encoding='UTF-8'),
        required=True,
        help='Dump to this file',
    )
    parser.add_argument('--data', required=True, help='Data directory')
    parser.add_argument('--testnet', action='store_true', help='Connect to Hathor the default testnet')
    parser.add_argument('--peer', help='Json file with peer info')
    parser.add_argument(
        '--start-block', type=str, help='Start the dump at a specific block hash (in hex), defaults to best block'
    )

    storage_group = parser.add_mutually_exclusive_group()
    storage_group.add_argument('--local', action='store_true', help='Dump the local storage from `--data` (default)')
    storage_group.add_argument('--address', type=str, help='Dump a remote peer storage (e.g. tcp://127.0.0.1:40403)')

    stop_group = parser.add_mutually_exclusive_group()
    stop_group.add_argument(
        '--until-complete', action='store_true', help='Stop the dump at the start of Nanos (default)'
    )
    stop_group.add_argument(
        '--until-block', type=str, help='Stop the dump at a specific block hash (in hex), inclusive'
    )
    stop_group.add_argument(
        '--until-height', type=int, help='Stop the dump at a specific block height, inclusive'
    )
    stop_group.add_argument(
        '--until-common',
        action='store_true',
        help='For diverging storages, stop the dump when both storages match, inclusive.'
    )

    return parser

def main() -> None:
    from hathor.reactor import initialize_global_reactor
    from hathor.nanocontracts.nc_dump.remote_nc_dumper import RemoteNCDumper
    from hathor.nanocontracts.nc_dump.local_nc_dumper import LocalNCDumper
    from hathor.conf.get_settings import get_global_settings
    from hathor.transaction.storage import TransactionRocksDBStorage
    from hathor.conf import TESTNET_INDIA_SETTINGS_FILEPATH
    from hathor.builder import Builder
    from hathor.nanocontracts.nc_dump.nc_dumper import NCDumper
    from hathor.p2p.peer import PrivatePeer
    from hathor.nanocontracts.nc_dump.nc_dumper import DumpMode, DumpUntilBlock, DumpUntilHeight, DumpUntilCommon, \
        DumpUntilComplete
    from hathor.transaction.storage.exceptions import TransactionDoesNotExist

    parser = create_parser()
    args = parser.parse_args()

    if args.testnet:
        os.environ['HATHOR_CONFIG_YAML'] = TESTNET_INDIA_SETTINGS_FILEPATH

    peer: PrivatePeer
    if args.peer:
        peer = PrivatePeer.create_from_json_path(args.peer)
    else:
        peer = PrivatePeer.auto_generated()

    reactor = initialize_global_reactor()
    settings = get_global_settings()
    builder = Builder() \
        .set_reactor(reactor) \
        .set_settings(settings) \
        .set_peer(peer) \
        .set_rocksdb_path(args.data)

    artifacts = builder.build()
    assert isinstance(artifacts.tx_storage, TransactionRocksDBStorage)

    dump_mode: DumpMode
    nc_dumper: NCDumper

    start_block: bytes | None = None
    if args.start_block:
        start_block = bytes.fromhex(args.start_block)
        try:
            artifacts.tx_storage.get_block(start_block)
        except TransactionDoesNotExist:
            logger.error('local storage does not contain start block', block=args.start_block)
            return

    if args.until_block:
        block_id = bytes.fromhex(args.until_block)
        try:
            artifacts.tx_storage.get_block(block_id)
        except TransactionDoesNotExist:
            logger.error('local storage does not contain block', block=args.until_block)
            return
        dump_mode = DumpUntilBlock(block_id)
    elif args.until_height:
        best_block = artifacts.tx_storage.get_best_block()
        if args.until_height > best_block.get_height():
            logger.error(
                'local storage does not contain height',
                height=args.until_height,
                local_best_height=best_block.get_height(),
            )
            return
        dump_mode = DumpUntilHeight(args.until_height)
    elif args.until_common:
        if not args.address:
            raise ValueError('cannot dump `--until-common` with a local storage, use `--address`')
        dump_mode = DumpUntilCommon()
    else:
        dump_mode = DumpUntilComplete()

    if args.address:
        nc_dumper = RemoteNCDumper(
            settings=settings,
            reactor=reactor,
            tx_storage=artifacts.tx_storage,
            start_block=start_block,
            out=args.dump_to,
            mode=dump_mode,
            address=args.address,
            peer=peer,
        )
    else:
        nc_dumper = LocalNCDumper(
            settings=settings,
            tx_storage=artifacts.tx_storage,
            start_block=start_block,
            out=args.dump_to,
            mode=dump_mode,
        )

    async def dump():
        try:
            await nc_dumper.dump()
        except Exception:
            logger.exception('error in NCDumper')
        await deferLater(reactor, 0, lambda: None)  # To make sure the reactor is running in the local (non-async) case
        reactor.stop()

    Deferred.fromCoroutine(dump())
    reactor.run()
