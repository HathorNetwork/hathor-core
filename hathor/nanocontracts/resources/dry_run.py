#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""HTTP resource for dry-running NC block execution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Union

import structlog
from pydantic import Field, model_validator
from twisted.internet.defer import Deferred
from twisted.internet.threads import deferToThread

from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api.schemas.base import ConflictResponse, ErrorResponse, NotFoundResponse
from hathor.api_util import Resource
from hathor.nanocontracts.execution.dry_run_block_executor import DryRunResult, NCDryRunBlockExecutor
from hathor.nanocontracts.execution.dry_run_utils import (
    DryRunConflictError,
    DryRunNotFoundError,
    DryRunValidationError,
    resolve_block_for_dry_run,
)
from hathor.utils.api import QueryParams

logger = structlog.get_logger()

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


class NCDryRunParams(QueryParams):
    """Query parameters for the dry-run endpoint."""
    block_hash: Optional[str] = Field(default=None, description="Hex-encoded block hash (64 chars)")
    tx_hash: Optional[str] = Field(default=None, description="Hex-encoded NC transaction hash (64 chars)")
    include_changes: bool = Field(default=False, description="Include storage state changes in call records")

    @model_validator(mode='after')
    def check_exactly_one_hash(self) -> 'NCDryRunParams':
        if self.block_hash and self.tx_hash:
            raise ValueError('Cannot specify both block_hash and tx_hash')
        if not self.block_hash and not self.tx_hash:
            raise ValueError('Must specify either block_hash or tx_hash')
        return self


@register_resource
class NCDryRunResource(Resource):
    """Resource for dry-running NC block execution.

    This endpoint allows inspecting what would happen during NC execution
    without modifying any state.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager') -> None:
        super().__init__()
        self.manager = manager

    @api_endpoint(
        path='/nano_contract/dry_run',
        method='GET',
        operation_id='nano_contracts_dry_run',
        summary='Dry-run NC block execution',
        description='Dry-run nano contract execution for a block without modifying state.',
        tags=['nano_contracts'],
        visibility='private',
        rate_limit_global=[{'rate': '2r/s', 'burst': 5, 'delay': 2}],
        rate_limit_per_ip=[{'rate': '1r/s', 'burst': 2, 'delay': 1}],
        query_params_model=NCDryRunParams,
        response_model=Union[DryRunResult, ErrorResponse, NotFoundResponse, ConflictResponse],
    )
    def render_GET(self, request: 'Request', *, params: NCDryRunParams) -> Union[bytes, Deferred]:
        request.setHeader(b'cache-control', b'no-store')

        logger.info('nc_dry_run.start', block_hash=params.block_hash, tx_hash=params.tx_hash)

        try:
            target = resolve_block_for_dry_run(
                self.manager.tx_storage,
                block_hash=params.block_hash,
                tx_hash=params.tx_hash,
            )
        except DryRunValidationError as e:
            return ErrorResponse(error=str(e))
        except DryRunConflictError as e:
            return ConflictResponse(error=str(e))
        except DryRunNotFoundError as e:
            return NotFoundResponse(error=str(e))

        logger.info('nc_dry_run.resolved', block_hash=target.block.hash.hex())

        # Execute dry run in a thread to avoid blocking the reactor
        def _execute() -> DryRunResult:
            dry_run_executor = NCDryRunBlockExecutor(self.manager.consensus_algorithm._block_executor)
            return dry_run_executor.execute(
                target.block,
                include_changes=params.include_changes,
                target_tx_hash=target.target_tx_hash,
            )

        return deferToThread(_execute)
