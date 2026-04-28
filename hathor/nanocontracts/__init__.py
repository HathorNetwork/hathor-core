# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCRocksDBStorageFactory, NCStorageFactory
from hathor.nanocontracts.types import TokenUid, VertexId, export, fallback, public, view
from hathorlib.conf import settings

# Identifier used in metadata's voided_by when a Nano Contract method fails.
NC_EXECUTION_FAIL_ID: bytes = b'nc-fail'
HATHOR_TOKEN_UID: TokenUid = TokenUid(VertexId(settings.HATHOR_TOKEN_UID))


__all__ = [
    'Blueprint',
    'Context',
    'Runner',
    'OnChainBlueprint',
    'NCFail',
    'NCRocksDBStorageFactory',
    'NCStorageFactory',
    'public',
    'fallback',
    'view',
    'export',
    'NC_EXECUTION_FAIL_ID',
    'HATHOR_TOKEN_UID',
]
