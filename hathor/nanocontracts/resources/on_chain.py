# Copyright 2025 Hathor Labs
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

from enum import Enum
from typing import Literal

from pydantic import Field
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.manager import HathorManager
from hathor.nanocontracts.exception import (
    BlueprintDoesNotExist,
    OCBBlueprintNotConfirmed,
    OCBInvalidBlueprintVertexType,
)
from hathor.nanocontracts.types import blueprint_id_from_bytes
from hathor.util import bytes_from_hex
from hathor.utils.api import ErrorResponse, QueryParams, Response


@register_resource
class BlueprintOnChainResource(Resource):
    """Implements a GET API to return a list of on-chain blueprints."""
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        tx_storage = self.manager.tx_storage
        if tx_storage.indexes.blueprints is None:
            request.setResponseCode(503)
            error_response = ErrorResponse(success=False, error='Blueprint index not initialized')
            return error_response.json_dumpb()

        bp_index = tx_storage.indexes.blueprints

        params = OnChainBlueprintsParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        if params.after and params.before:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error='Parameters after and before can\'t be used together.')
            return error_response.json_dumpb()

        if params.search:
            search = params.search.strip()
            blueprint_list = []
            if bp_id := bytes_from_hex(search):
                try:
                    bp_tx = tx_storage.get_on_chain_blueprint(blueprint_id_from_bytes(bp_id))
                except (BlueprintDoesNotExist, OCBInvalidBlueprintVertexType, OCBBlueprintNotConfirmed):
                    pass
                else:
                    executor = self.manager.runner_factory.executor_factory.for_loading()
                    bp_class = bp_tx.get_blueprint_class(executor)
                    bp_item = OnChainBlueprintItem(
                        id=search,
                        name=bp_class.__name__,
                        created_at=bp_tx.timestamp,
                    )
                    blueprint_list = [bp_item] if not params.after and not params.before else []

            response = OnChainBlueprintsResponse(
                blueprints=blueprint_list,
                before=params.before,
                after=params.after,
                count=params.count,
                has_more=False,
            )
            return response.json_dumpb()

        if not params.before and not params.after:
            iter_bps = bp_index.get_newest() if params.order.is_desc() else bp_index.get_oldest()
        else:
            ref_tx_id = bytes.fromhex(params.before or params.after or '')
            assert ref_tx_id
            try:
                ref_tx = tx_storage.get_on_chain_blueprint(blueprint_id_from_bytes(ref_tx_id))
            except (BlueprintDoesNotExist, OCBInvalidBlueprintVertexType, OCBBlueprintNotConfirmed) as e:
                request.setResponseCode(404)
                error_response = ErrorResponse(
                    success=False, error=f'Blueprint not found: {repr(e)}'
                )
                return error_response.json_dumpb()

            if params.order.is_desc():
                iter_bps_getter = bp_index.get_newer if params.before else bp_index.get_older
            else:
                iter_bps_getter = bp_index.get_older if params.before else bp_index.get_newer
            iter_bps = iter_bps_getter(tx_start=ref_tx)

        has_more = False
        blueprints = []
        for idx, bp_id in enumerate(iter_bps):
            try:
                bp_tx = tx_storage.get_on_chain_blueprint(blueprint_id_from_bytes(bp_id))
            except (BlueprintDoesNotExist, OCBInvalidBlueprintVertexType):
                raise AssertionError('bps iterator must always yield valid blueprint txs')
            except OCBBlueprintNotConfirmed:
                # unconfirmed OCBs are simply not added to the response
                continue
            executor = self.manager.runner_factory.executor_factory.for_loading()
            bp_class = bp_tx.get_blueprint_class(executor)
            bp_item = OnChainBlueprintItem(
                id=bp_id.hex(),
                name=bp_class.__name__,
                created_at=bp_tx.timestamp,
            )
            blueprints.append(bp_item)
            if idx >= params.count - 1:
                try:
                    next(iter_bps)
                    has_more = True
                except StopIteration:
                    has_more = False
                break

        response = OnChainBlueprintsResponse(
            blueprints=blueprints,
            before=params.before,
            after=params.after,
            count=params.count,
            has_more=has_more,
        )
        return response.json_dumpb()


class SortOrder(str, Enum):
    ASC = 'asc'
    DESC = 'desc'

    def is_desc(self) -> bool:
        return self == SortOrder.DESC


class OnChainBlueprintsParams(QueryParams):
    before: str | None = None
    after: str | None = None
    count: int = Field(default=10, le=100)
    search: str | None = None
    order: SortOrder = SortOrder.DESC


class OnChainBlueprintItem(Response):
    id: str
    name: str
    created_at: int


class OnChainBlueprintsResponse(Response):
    success: Literal[True] = True
    blueprints: list[OnChainBlueprintItem]
    before: str | None
    after: str | None
    count: int
    has_more: bool


BlueprintOnChainResource.openapi = {
    '/nano_contract/blueprint/on_chain': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '100r/s',
                    'burst': 100,
                    'delay': 100
                }
            ],
            'per-ip': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'operationId': 'on-chain-blueprints',
            'summary': 'Return a list of on-chain blueprints',
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
                    'description': 'Filter the list using the provided string, that can be a Blueprint ID.',
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
                                      'blueprints': [
                                        {
                                          'id': '0000035c5977ff42c40e6845f91d72af4feb06ce87ce9f50119b5d00e0906458',
                                          'name': 'BlueprintA',
                                          'created_at': 1736353724
                                        },
                                        {
                                          'id': '0000010881987e7fcce37cac7c1342f6f81b0a8e2f9c8ba6377a6272d433366e',
                                          'name': 'BlueprintB',
                                          'created_at': 1736351322
                                        }
                                      ],
                                      'before': None,
                                      'after': None,
                                      'count': 2,
                                      'has_more': True
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
