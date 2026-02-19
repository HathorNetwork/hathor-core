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

from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field

from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api.schemas import SuccessResponse
from hathor.api_util import Resource, set_cors
from hathor.types import TransactionId
from hathor.utils.api import ErrorResponse, QueryParams, Response
from hathor.utils.pydantic import Hex

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


class BlockAtHeightParams(QueryParams):
    """Query parameters for the /block_at_height endpoint."""
    height: int = Field(description="Height of the block to get")
    include_transactions: str | None = Field(
        default=None,
        description="Add transactions confirmed by this block ('txid' for IDs only, 'full' for full tx data)"
    )


class BlockAtHeightSuccessResponse(SuccessResponse):
    """Success response for /block_at_height endpoint."""
    block: dict[str, Any] = Field(description="Block data in extended JSON format")
    tx_ids: list[Hex[TransactionId]] | None = Field(
        default=None,
        description="Transaction IDs confirmed by this block (when include_transactions='txid')"
    )
    transactions: list[dict[str, Any]] | None = Field(
        default=None,
        description="Full transaction data confirmed by this block (when include_transactions='full')"
    )


class BlockAtHeightErrorResponse(Response):
    """Error response for /block_at_height endpoint."""
    success: Literal[False] = False
    message: str = Field(description="Error message")


@register_resource
class BlockAtHeightResource(Resource):
    """ Implements a web server API to return the block at specific height.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    @api_endpoint(
        path='/block_at_height',
        method='GET',
        operation_id='block_at_height',
        summary='Get block at height',
        description='Returns the block at specific height in the best chain.',
        tags=['block'],
        visibility='public',
        rate_limit_global=[{'rate': '50r/s', 'burst': 100, 'delay': 50}],
        rate_limit_per_ip=[{'rate': '3r/s', 'burst': 10, 'delay': 3}],
        query_params_model=BlockAtHeightParams,
        response_model=BlockAtHeightSuccessResponse,
        error_responses=[BlockAtHeightErrorResponse],
    )
    def render_GET(self, request: 'Request') -> bytes:
        """ Get request /block_at_height/ that returns a block at height in parameter

            'height': int, the height of block to get

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = BlockAtHeightParams.from_request(request)
        if isinstance(params, ErrorResponse):
            return params.json_dumpb()

        # Get hash of the block with the height
        block_hash = self.manager.tx_storage.indexes.height.get(params.height)

        # If there is no block in the index with this height, block_hash will be None
        if block_hash is None:
            error_response = BlockAtHeightErrorResponse(
                message='No block with height {}.'.format(params.height)
            )
            return error_response.json_dumpb()

        block = self.manager.tx_storage.get_block(block_hash)
        block_data = block.to_json_extended()

        tx_ids: list[TransactionId] | None = None
        transactions: list[dict[str, Any]] | None = None

        if params.include_transactions is None:
            pass

        elif params.include_transactions == 'txid':
            tx_ids = []
            for tx in block.iter_transactions_in_this_block():
                tx_ids.append(TransactionId(tx.hash))

        elif params.include_transactions == 'full':
            transactions = []
            for tx in block.iter_transactions_in_this_block():
                transactions.append(tx.to_json_extended())

        else:
            error_response = BlockAtHeightErrorResponse(
                message='Invalid include_transactions. Choices are: txid or full.'
            )
            return error_response.json_dumpb()

        response = BlockAtHeightSuccessResponse(
            block=block_data,
            tx_ids=tx_ids,
            transactions=transactions,
        )
        return response.json_dumpb()
