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

from pydantic import Field
from twisted.web.http import Request

from hathor.api_util import Resource, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.manager import HathorManager
from hathor.nanocontracts import NanoContract
from hathor.nanocontracts.resources.on_chain import SortOrder
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import collect_n, not_none
from hathor.utils.api import ErrorResponse, QueryParams, Response


@register_resource
class NCCreationResource(Resource):
    """Implements a GET API to return a list of NC creation txs."""
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager
        self.tx_storage = self.manager.tx_storage
        assert self.tx_storage.indexes is not None
        self.nc_creation_index = self.tx_storage.indexes.nc_creation
        self.nc_history_index = self.tx_storage.indexes.nc_history
        self.bp_history_index = self.tx_storage.indexes.blueprint_history

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.nc_creation_index or not self.nc_history_index or not self.bp_history_index:
            request.setResponseCode(503)
            error_response = ErrorResponse(success=False, error='NC indices not initialized')
            return error_response.json_dumpb()

        params = NCCreationParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        if params.after and params.before:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error='Parameters after and before can\'t be used together.')
            return error_response.json_dumpb()

        if params.find_blueprint_name:
            request.setResponseCode(400)
            error_response = ErrorResponse(
                success=False, error='Searching by blueprint name is currently not supported.'
            )
            return error_response.json_dumpb()

        if params.find_nano_contract_id:
            if params.after or params.before:
                request.setResponseCode(400)
                error_response = ErrorResponse(
                    success=False,
                    error='Parameters after and before can\'t be used with find_nano_contract_id.'
                )
                return error_response.json_dumpb()

            try:
                nc_id = bytes.fromhex(params.find_nano_contract_id)
            except ValueError:
                request.setResponseCode(400)
                error_response = ErrorResponse(
                    success=False,
                    error=f'Invalid nano_contract_id: {params.find_nano_contract_id}'
                )
                return error_response.json_dumpb()

            nc_item = self._get_nc_creation_item(nc_id)
            nc_list = [nc_item] if nc_item else []
            response = NCCreationResponse(
                nc_creation_txs=nc_list,
                before=params.before,
                after=params.after,
                count=params.count,
                has_more=False,
            )
            return response.json_dumpb()

        try:
            bp_id = bytes.fromhex(params.find_blueprint_id) if params.find_blueprint_id else None
        except ValueError:
            request.setResponseCode(400)
            error_response = ErrorResponse(
                success=False,
                error=f'Invalid blueprint_id: {params.find_blueprint_id}'
            )
            return error_response.json_dumpb()

        is_desc = params.order.is_desc()

        if not params.before and not params.after:
            if bp_id:
                iter_nc_ids = (
                    self.bp_history_index.get_newest(bp_id) if is_desc else self.bp_history_index.get_oldest(bp_id)
                )
            else:
                iter_nc_ids = self.nc_creation_index.get_newest() if is_desc else self.nc_creation_index.get_oldest()
        else:
            ref_tx_id = params.before or params.after
            assert ref_tx_id is not None
            try:
                ref_tx = self.tx_storage.get_transaction(bytes.fromhex(ref_tx_id))
            except TransactionDoesNotExist:
                request.setResponseCode(404)
                error_response = ErrorResponse(success=False, error=f'Transaction {ref_tx_id} not found.')
                return error_response.json_dumpb()

            if bp_id:
                if is_desc:
                    iter_getter = self.bp_history_index.get_newer if params.before else self.bp_history_index.get_older
                else:
                    iter_getter = self.bp_history_index.get_older if params.before else self.bp_history_index.get_newer
                iter_nc_ids = iter_getter(bp_id, ref_tx)
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

        iter_ncs = map(self._get_nc_creation_item_strict, iter_nc_ids)
        nc_txs, has_more = collect_n(iter_ncs, params.count)
        response = NCCreationResponse(
            nc_creation_txs=nc_txs,
            before=params.before,
            after=params.after,
            count=params.count,
            has_more=has_more,
        )
        return response.json_dumpb()

    def _get_nc_creation_item(self, nc_id: bytes) -> NCCreationItem | None:
        try:
            tx = self.tx_storage.get_transaction(nc_id)
        except TransactionDoesNotExist:
            return None

        if not isinstance(tx, NanoContract) or not tx.is_creating_a_new_contract():
            return None

        assert self.nc_history_index is not None
        return NCCreationItem(
            nano_contract_id=nc_id.hex(),
            blueprint_id=tx.get_blueprint_id().hex(),
            blueprint_name=tx.get_blueprint_class().__name__,
            last_tx_timestamp=not_none(self.nc_history_index.get_last_tx_timestamp(nc_id)),
            total_txs=self.nc_history_index.get_transaction_count(nc_id),
            created_at=tx.timestamp,
        )

    def _get_nc_creation_item_strict(self, nc_id: bytes) -> NCCreationItem:
        tx = self._get_nc_creation_item(nc_id)
        assert tx is not None
        return tx


class NCCreationParams(QueryParams):
    before: str | None
    after: str | None
    count: int = Field(default=10, le=100)
    find_nano_contract_id: str | None
    find_blueprint_id: str | None
    find_blueprint_name: str | None
    order: SortOrder = SortOrder.DESC


class NCCreationItem(Response):
    nano_contract_id: str
    blueprint_id: str
    blueprint_name: str
    last_tx_timestamp: int
    total_txs: int
    created_at: int


class NCCreationResponse(Response):
    success: bool = Field(default=True, const=True)
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
                    'name': 'find_nano_contract_id',
                    'in': 'query',
                    'description': 'Filter the list using the provided Nano Contract ID.',
                    'required': False,
                    'schema': {
                        'type': 'string',
                    }
                },
                {
                    'name': 'find_blueprint_id',
                    'in': 'query',
                    'description': 'Filter the list using the provided Blueprint ID.',
                    'required': False,
                    'schema': {
                        'type': 'string',
                    }
                },
                {
                    'name': 'find_blueprint_name',
                    'in': 'query',
                    'description': 'Filter the list using the provided Blueprint name.',
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
