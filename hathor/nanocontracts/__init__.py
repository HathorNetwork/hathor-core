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

from hathor.conf import settings
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCMemoryStorageFactory, NCRocksDBStorageFactory, NCStorageFactory
from hathor.nanocontracts.types import TokenUid, VertexId, fallback, public, view

# Identifier used in metadata's voided_by when a Nano Contract method fails.
NC_EXECUTION_FAIL_ID: bytes = b'nc-fail'
HATHOR_TOKEN_UID: TokenUid = TokenUid(VertexId(settings.HATHOR_TOKEN_UID))


__all__ = [
    'Blueprint',
    'Context',
    'Runner',
    'OnChainBlueprint',
    'NCFail',
    'NCMemoryStorageFactory',
    'NCRocksDBStorageFactory',
    'NCStorageFactory',
    'public',
    'fallback',
    'view',
    'NC_EXECUTION_FAIL_ID',
    'HATHOR_TOKEN_UID',
]
