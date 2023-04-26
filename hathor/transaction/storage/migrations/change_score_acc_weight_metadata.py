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

from typing import TYPE_CHECKING

from hathor.transaction.storage.migrations import BaseMigration

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage


class Migration(BaseMigration):
    def skip_empty_db(self) -> bool:
        return True

    def get_db_name(self) -> str:
        return 'change_score_acc_weight_metadata'

    def run(self, storage: 'TransactionStorage') -> None:
        raise Exception('Cannot migrate your database due to an incompatible change in the metadata. '
                        'Please, delete your data folder and use the latest available snapshot or sync '
                        'from beginning.')
