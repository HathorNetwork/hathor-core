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

from typing import TYPE_CHECKING, Optional

from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api_util import Resource, set_cors
from hathor.nanocontracts.execution.dry_run_block_executor import DryRunResult, NCDryRunBlockExecutor
from hathor.utils.api import ErrorResponse, QueryParams

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager
    from hathor.transaction import Block


class NCDryRunParams(QueryParams):
    """Query parameters for the dry-run endpoint."""
    block_hash: Optional[str] = None
    tx_hash: Optional[str] = None
    include_changes: bool = False


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
        visibility='public',
        rate_limit_global=[{'rate': '10r/s', 'burst': 10, 'delay': 5}],
        rate_limit_per_ip=[{'rate': '2r/s', 'burst': 3, 'delay': 1}],
        query_params_model=NCDryRunParams,
        response_model=DryRunResult,
        error_responses=[ErrorResponse],
    )
    def render_GET(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = NCDryRunParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        # Validate that exactly one of block_hash or tx_hash is provided
        if params.block_hash and params.tx_hash:
            request.setResponseCode(400)
            error = ErrorResponse(success=False, error='Cannot specify both block_hash and tx_hash')
            return error.json_dumpb()

        if not params.block_hash and not params.tx_hash:
            request.setResponseCode(400)
            error = ErrorResponse(success=False, error='Must specify either block_hash or tx_hash')
            return error.json_dumpb()

        block: Block
        target_tx_hash: Optional[str] = None

        if params.tx_hash:
            # Get transaction and find its first_block
            try:
                tx_hash_bytes = bytes.fromhex(params.tx_hash)
            except ValueError:
                request.setResponseCode(400)
                error = ErrorResponse(success=False, error=f'Invalid tx_hash: {params.tx_hash}')
                return error.json_dumpb()

            try:
                tx = self.manager.tx_storage.get_transaction(tx_hash_bytes)
            except Exception:
                request.setResponseCode(404)
                error = ErrorResponse(success=False, error=f'Transaction not found: {params.tx_hash}')
                return error.json_dumpb()

            if not tx.is_nano_contract():
                request.setResponseCode(400)
                error = ErrorResponse(success=False, error='Transaction is not a nano contract')
                return error.json_dumpb()

            tx_meta = tx.get_metadata()
            if tx_meta.first_block is None:
                request.setResponseCode(400)
                error = ErrorResponse(success=False, error='Transaction has no first_block')
                return error.json_dumpb()

            try:
                block = self.manager.tx_storage.get_block(tx_meta.first_block)
            except Exception:
                request.setResponseCode(404)
                error = ErrorResponse(success=False, error=f'Block not found: {tx_meta.first_block.hex()}')
                return error.json_dumpb()

            target_tx_hash = params.tx_hash
        else:
            # Get block directly
            assert params.block_hash is not None
            try:
                block_hash_bytes = bytes.fromhex(params.block_hash)
            except ValueError:
                request.setResponseCode(400)
                error = ErrorResponse(success=False, error=f'Invalid block_hash: {params.block_hash}')
                return error.json_dumpb()

            try:
                block = self.manager.tx_storage.get_block(block_hash_bytes)
            except Exception:
                request.setResponseCode(404)
                error = ErrorResponse(success=False, error=f'Block not found: {params.block_hash}')
                return error.json_dumpb()

        # Validate block state
        block_meta = block.get_metadata()
        if block_meta.voided_by:
            request.setResponseCode(400)
            error = ErrorResponse(success=False, error='Block is not on best chain (voided)')
            return error.json_dumpb()

        if block.is_genesis:
            request.setResponseCode(400)
            error = ErrorResponse(success=False, error='Cannot dry-run genesis block')
            return error.json_dumpb()

        # Execute dry run using shared executor
        try:
            dry_run_executor = NCDryRunBlockExecutor(self.manager.consensus_algorithm._block_executor)
            result = dry_run_executor.execute(
                block,
                include_changes=params.include_changes,
                target_tx_hash=target_tx_hash,
            )
        except Exception as e:
            request.setResponseCode(500)
            error = ErrorResponse(success=False, error=f'Dry run failed: {str(e)}')
            return error.json_dumpb()

        # Return result directly using pydantic's json_dumpb
        request.setResponseCode(200)
        return result.json_dumpb()
