# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from argparse import ArgumentParser, Namespace

from structlog import get_logger

logger = get_logger()


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser

    parser = create_parser()
    parser.add_argument('--data', help='Data directory')

    return parser


def execute(args: Namespace) -> None:
    from hathor.event.storage import EventRocksDBStorage
    from hathor.storage import RocksDBStorage

    assert args.data is not None, '--data is required'

    rocksdb_storage = RocksDBStorage(path=args.data)
    event_storage = EventRocksDBStorage(rocksdb_storage)

    logger.info('removing all events and related data...')
    event_storage.reset_all()
    logger.info('reset complete')


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
