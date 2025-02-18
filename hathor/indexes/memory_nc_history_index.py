# Copyright 2023 Hathor Labs
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

from structlog import get_logger

from hathor.indexes.memory_tx_group_index import MemoryTxGroupIndex
from hathor.indexes.nc_history_index import NCHistoryIndex

logger = get_logger()


class MemoryNCHistoryIndex(MemoryTxGroupIndex[bytes], NCHistoryIndex):
    """In-memory index of all transactions of a Nano Contract."""
