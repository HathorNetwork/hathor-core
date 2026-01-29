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

from typing import Iterator, Literal

from pydantic import ConfigDict, Field
from sortedcontainers import SortedKeyList
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.manager import HathorManager
from hathor.nanocontracts import Blueprint
from hathor.util import collect_n
from hathor.utils.api import ErrorResponse, QueryParams, Response


@register_resource
class BlueprintBuiltinResource(Resource):
    """Implements a GET API to return a list of builtin blueprints."""
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = BuiltinBlueprintsParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        if params.after and params.before:
            request.setResponseCode(400)
            error_response = ErrorResponse(
              success=False, error='Parameters after and before can\'t be used together.')
            return error_response.json_dumpb()

        assert self.manager.tx_storage.nc_catalog is not None
        builtin_bps = list(self.manager.tx_storage.nc_catalog.blueprints.items())

        filtered_bps = builtin_bps
        if params.search:
            search = params.search.strip().lower()
            # first we try to find by blueprint ID
            filtered_bps = [
                (bp_id, bp_class) for bp_id, bp_class in builtin_bps
                if bp_id.hex().lower() == search
            ]

            if filtered_bps:
                # If we find the Blueprint, it's a single match, and any pagination returns empty.
                assert len(filtered_bps) == 1
                if params.after or params.before:
                    filtered_bps = []
            else:
                # If we didn't find it, we'll try by name
                filtered_bps = [
                    (bp_id, bp_class) for bp_id, bp_class in builtin_bps
                    if search in bp_class.__name__.lower()
                ]

        sorted_bps = SortedKeyList(filtered_bps, key=lambda bp_id_and_class: bp_id_and_class[0])
        reverse = bool(params.before)
        start_key = bytes.fromhex(params.before or params.after or '') or None
        bp_iter: Iterator[tuple[bytes, type[Blueprint]]] = sorted_bps.irange_key(
            min_key=None if reverse else start_key,
            max_key=start_key if reverse else None,
            reverse=reverse,
            inclusive=(False, False),
        )
        page, has_more = collect_n(bp_iter, params.count)

        blueprints = [
            BuiltinBlueprintItem(id=bp_id.hex(), name=bp_class.__name__)
            for bp_id, bp_class in page
        ]

        response = BuiltinBlueprintsResponse(
            before=params.before,
            after=params.after,
            count=params.count,
            has_more=has_more,
            blueprints=blueprints,
        )
        return response.json_dumpb()


class BuiltinBlueprintsParams(QueryParams):
    model_config = ConfigDict(use_enum_values=True)

    before: str | None = None
    after: str | None = None
    count: int = Field(default=10, gt=0, le=100)
    search: str | None = None


class BuiltinBlueprintItem(Response):
    id: str
    name: str


class BuiltinBlueprintsResponse(Response):
    success: Literal[True] = True
    blueprints: list[BuiltinBlueprintItem]
    before: str | None
    after: str | None
    count: int
    has_more: bool


BlueprintBuiltinResource.openapi = {
    '/nano_contract/blueprint/builtin': {
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
            'operationId': 'builtin-blueprints',
            'summary': 'Return a list of builtin blueprints',
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
                    'description': 'Filter the list using the provided string, that could be a Blueprint ID or name.',
                    'required': False,
                    'schema': {
                        'type': 'string',
                    }
                },
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
                                        'before': None,
                                        'after': None,
                                        'count': 10,
                                        'has_more': False,
                                        'blueprints': [
                                            {
                                                'id': '3cb032600bdf7db784800e4ea911b106'
                                                      '76fa2f67591f82bb62628c234e771595',
                                                'name': 'Bet'
                                            }
                                        ],
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
