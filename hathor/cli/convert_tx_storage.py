""" Convert a tx database from one storage to another.
"""

import os
from argparse import ArgumentParser, Namespace
from typing import TYPE_CHECKING

from tqdm import tqdm

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('source', help='Source storage type. [type:path]')
    parser.add_argument('destination', help='Destination storage type. [type:path]')
    return parser


def get_tx_storage(storage_type: str, path: str) -> 'TransactionStorage':
    tx_storage: 'TransactionStorage'
    if storage_type == 'rocksdb':
        from hathor.transaction.storage import TransactionRocksDBStorage
        tx_dir = os.path.join(path, 'tx.db')
        tx_storage = TransactionRocksDBStorage(path=tx_dir)
    else:
        tx_dir = os.path.join(path, 'tx')
        if storage_type == 'compact':
            from hathor.transaction.storage import TransactionCompactStorage
            tx_storage = TransactionCompactStorage(path=tx_dir)
        elif storage_type == 'binary':
            from hathor.transaction.storage import TransactionBinaryStorage
            tx_storage = TransactionBinaryStorage(path=tx_dir)
    return tx_storage


def execute(args: Namespace) -> None:
    src_type, src_path = args.source.split(':', 1)
    dst_type, dst_path = args.destination.split(':', 1)

    src_storage = get_tx_storage(src_type, src_path)
    dst_storage = get_tx_storage(dst_type, dst_path)

    print('Source: {}'.format(repr(src_storage)))
    print('Destination: {}'.format(repr(dst_storage)))
    print()

    total = src_storage.get_count_tx_blocks()
    print('Total transactions: {}'.format(total))
    print()

    with tqdm(total=total) as pbar:
        for tx in src_storage.get_all_transactions():
            dst_storage.save_transaction(tx)
            pbar.update(1)


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
