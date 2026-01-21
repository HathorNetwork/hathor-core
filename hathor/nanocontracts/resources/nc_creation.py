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

from __future__ import annotations

from typing import Literal

from pydantic import Field
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.manager import HathorManager
from hathor.nanocontracts.exception import NanoContractDoesNotExist
from hathor.nanocontracts.resources.on_chain import SortOrder
from hathor.nanocontracts.types import BlueprintId, VertexId
from hathor.transaction import Transaction
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import bytes_from_hex, not_none
from hathor.utils.api import ErrorResponse, QueryParams, Response


@register_resource
class NCCreationResource(Resource):
    """Implements a GET API to return a list of NC creation txs."""
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager
        self.tx_storage = self.manager.tx_storage
        self.nc_creation_index = self.tx_storage.indexes.nc_creation
        self.nc_history_index = self.tx_storage.indexes.nc_history
        self.bp_history_index = self.tx_storage.indexes.blueprint_history

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.nc_creation_index or not self.nc_history_index or not self.bp_history_index:
            request.setResponseCode(503)
            error_response = ErrorResponse(success=False, error='NC indexes not initialized, use --nc-indexes')
            return error_response.json_dumpb()

        params = NCCreationParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        if params.after and params.before:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error='Parameters after and before can\'t be used together.')
            return error_response.json_dumpb()

        vertex_id: VertexId | None = None
        if params.search:
            search = params.search.strip()
            maybe_bytes = bytes_from_hex(search)
            if maybe_bytes is None:
                # in this case we do have `search` but it's not a valid hex, so we return empty.
                response = NCCreationResponse(
                    nc_creation_txs=[],
                    before=params.before,
                    after=params.after,
                    count=params.count,
                    has_more=False,
                )
                return response.json_dumpb()

            vertex_id = VertexId(maybe_bytes)

            # when using `search`, the value can be either a NC ID or a BP ID.
            if nc_item := self._get_nc_creation_item(vertex_id):
                # if we find the respective NC, it's a single match, and therefore any pagination
                # returns an empty result.
                nc_list = [nc_item] if not params.after and not params.before else []
                response = NCCreationResponse(
                    nc_creation_txs=nc_list,
                    before=params.before,
                    after=params.after,
                    count=params.count,
                    has_more=False,
                )
                return response.json_dumpb()
            # now vertex_id may be a BP, so it will be used below

        is_desc = params.order.is_desc()

        if not params.before and not params.after:
            if vertex_id:
                iter_nc_ids = (
                    self.bp_history_index.get_newest(vertex_id)
                    if is_desc else self.bp_history_index.get_oldest(vertex_id)
                )
            else:
                iter_nc_ids = self.nc_creation_index.get_newest() if is_desc else self.nc_creation_index.get_oldest()
        else:
            ref_tx_id_hex = params.before or params.after
            assert ref_tx_id_hex is not None
            ref_tx_id = bytes_from_hex(ref_tx_id_hex)
            if ref_tx_id is None:
                request.setResponseCode(400)
                error_response = ErrorResponse(success=False, error=f'Invalid "before" or "after": {ref_tx_id_hex}')
                return error_response.json_dumpb()

            try:
                ref_tx = self.tx_storage.get_transaction(ref_tx_id)
            except TransactionDoesNotExist:
                request.setResponseCode(404)
                error_response = ErrorResponse(success=False, error=f'Transaction {ref_tx_id_hex} not found.')
                return error_response.json_dumpb()

            if vertex_id:
                if is_desc:
                    iter_getter = self.bp_history_index.get_newer if params.before else self.bp_history_index.get_older
                else:
                    iter_getter = self.bp_history_index.get_older if params.before else self.bp_history_index.get_newer
                iter_nc_ids = iter_getter(vertex_id, ref_tx)
                next(iter_nc_ids)  # these iterators include the ref_tx, so we skip it.
            else:
                if is_desc:
                    iter_getter2 = (
                        self.nc_creation_index.get_newer if params.before else self.nc_creation_index.get_older
                    )
                else:
                    iter_getter2 = (
                        self.nc_creation_index.get_older if params.before else self.nc_creation_index.get_newer
                    )
                iter_nc_ids = iter_getter2(tx_start=ref_tx)

        nc_txs: list[NCCreationItem] = []
        has_more = False
        for nc_id in iter_nc_ids:
            if len(nc_txs) >= params.count:
                has_more = True
                break
            if item := self._get_nc_creation_item(nc_id):
                nc_txs.append(item)

        response = NCCreationResponse(
            nc_creation_txs=nc_txs,
            before=params.before,
            after=params.after,
            count=params.count,
            has_more=has_more,
        )
        return response.json_dumpb()

    def _try_get_contract_creation_vertex(self, nc_id: bytes) -> Transaction | None:
        """Return a contract creation vertex if it exists. Otherwise, return None.
        """
        try:
            tx = self.tx_storage.get_transaction(nc_id)
        except TransactionDoesNotExist:
            return None

        if not tx.is_nano_contract():
            return None

        if not isinstance(tx, Transaction):
            return None

        nano_header = tx.get_nano_header()
        if not nano_header.is_creating_a_new_contract():
            return None

        return tx

    def _get_nc_creation_item(self, nc_id: bytes) -> NCCreationItem | None:
        tx = self._try_get_contract_creation_vertex(nc_id)
        if tx is not None:
            nano_header = tx.get_nano_header()
            blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
            blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
            created_at = tx.timestamp

        else:
            try:
                nc_storage = self.manager.get_best_block_nc_storage(nc_id)
            except NanoContractDoesNotExist:
                return None

            blueprint_id = nc_storage.get_blueprint_id()
            blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
            created_at = 0

        assert self.nc_history_index is not None
        return NCCreationItem(
            nano_contract_id=nc_id.hex(),
            blueprint_id=blueprint_id.hex(),
            blueprint_name=blueprint_class.__name__,
            last_tx_timestamp=not_none(self.nc_history_index.get_last_tx_timestamp(nc_id)),
            total_txs=self.nc_history_index.get_transaction_count(nc_id),
            created_at=created_at,
        )


class NCCreationParams(QueryParams):
    before: str | None = None
    after: str | None = None
    count: int = Field(default=10, le=100)
    search: str | None = None
    order: SortOrder = SortOrder.DESC


class NCCreationItem(Response):
    nano_contract_id: str
    blueprint_id: str
    blueprint_name: str
    last_tx_timestamp: int
    total_txs: int
    created_at: int


class NCCreationResponse(Response):
    success: Literal[True] = True
    nc_creation_txs: list[NCCreationItem]
    before: str | None
    after: str | None
    count: int
    has_more: bool


NCCreationResource.openapi = {
    '/nano_contract/creation': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
                }
            ],
            'per-ip': [
                {
                    'rate': '1r/s',
                    'burst': 4,
                    'delay': 2
                }
            ]
        },
        'get': {
            'tags': ['nano_contracts'],
            'operationId': 'nc-creations-txs',
            'summary': 'Get a list of Nano Contract creation transactions',
            'parameters': [
                {
                    'name': 'before',
                    'in': 'query',
                    'description': 'Hash of transaction to offset the result before.',
                    'required': False,
                    'schema': {
                        'type': 'string',
                    }
                },
                {
                    'name': 'after',
                    'in': 'query',
                    'description': 'Hash of transaction to offset the result after.',
                    'required': False,
                    'schema': {
                        'type': 'string',
                    }
                },
                {
                    'name': 'count',
                    'in': 'query',
                    'description': 'Maximum number of items to be returned. Default is 10.',
                    'required': False,
                    'schema': {
                        'type': 'int',
                    }
                },
                {
                    'name': 'search',
                    'in': 'query',
                    'description': 'Filter the list using the provided string,'
                                   'that could be a Nano Contract ID or a Blueprint ID.',
                    'required': False,
                    'schema': {
                        'type': 'string',
                    }
                },
                {
                    'name': 'order',
                    'in': 'query',
                    'description': 'Sort order, either "asc" or "desc".',
                    'required': False,
                    'schema': {
                        'type': 'string',
                    }
                }
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'after': None,
                                        'before': None,
                                        'count': 10,
                                        'has_more': False,
                                        'nc_creation_txs': [
                                            {
                                                'blueprint_id': '3cb032600bdf7db784800e4ea911b106'
                                                                '76fa2f67591f82bb62628c234e771595',
                                                'blueprint_name': 'BlueprintA',
                                                'created_at': 1737565681,
                                                'last_tx_timestamp': 1737565681,
                                                'nano_contract_id': '081c0e7586486d657353bc844b26dace'
                                                                    'aa93e54e2f0b65e9debf956e51a3805f',
                                                'total_txs': 1
                                            },
                                            {
                                                'blueprint_id': '15b9eb0547e0961259df84c400615a69'
                                                                'fc204fe8d026b93337c33f0b9377a5bd',
                                                'blueprint_name': 'BlueprintB',
                                                'created_at': 1737565679,
                                                'last_tx_timestamp': 1737565679,
                                                'nano_contract_id': '773cd47af52e55fca04ce3aecab585c9'
                                                                    '40b4661daf600956b3d60cff8fa186ed',
                                                'total_txs': 1
                                            }
                                        ]
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}
