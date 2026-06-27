# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING

from structlog import get_logger

from hathor.transaction.storage.migrations import BaseMigration

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class Migration(BaseMigration):
    def skip_empty_db(self) -> bool:
        return True

    def get_db_name(self) -> str:
        return 'include_funds_for_first_block'

    def run(self, storage: 'TransactionStorage') -> None:
        raise Exception('Cannot migrate your database due to an incompatible change in the metadata. '
                        'Please, delete your data folder and use the latest available snapshot or sync '
                        'from beginning.')
