# Copyright 2022 Hathor Labs
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

from typing import TYPE_CHECKING

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.nanocontracts.exception import BlueprintDoesNotExist, OCBBlueprintNotConfirmed
from hathor.nanocontracts.types import blueprint_id_from_bytes
from hathor.utils.api import ErrorResponse, QueryParams, Response

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


@register_resource
class BlueprintSourceCodeResource(Resource):
    """Implements a GET API to return the source code of a blueprint."""
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = BlueprintSourceCodeParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        try:
            blueprint_id = blueprint_id_from_bytes(bytes.fromhex(params.blueprint_id))
        except ValueError:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error=f'Invalid id: {params.blueprint_id}')
            return error_response.json_dumpb()

        assert self.manager.tx_storage.nc_catalog is not None

        try:
            blueprint_source = self.manager.tx_storage.get_blueprint_source(blueprint_id)
        except OCBBlueprintNotConfirmed:
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error=f'Blueprint not confirmed: {params.blueprint_id}')
            return error_response.json_dumpb()
        except BlueprintDoesNotExist:
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error=f'Blueprint not found: {params.blueprint_id}')
            return error_response.json_dumpb()

        response = BlueprintSourceCodeResponse(
            id=params.blueprint_id,
            source_code=blueprint_source,
        )
        return response.json_dumpb()


class BlueprintSourceCodeParams(QueryParams):
    blueprint_id: str


class BlueprintSourceCodeResponse(Response):
    id: str
    source_code: str


BlueprintSourceCodeResource.openapi = {
    '/nano_contract/blueprint/source': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '5r/s',
                    'burst': 8,
                    'delay': 3
                }
            ],
            'per-ip': [
                {
                    'rate': '2r/s',
                    'burst': 4,
                    'delay': 3
                }
            ]
        },
        'get': {
            'operationId': 'blueprint-source-code',
            'summary': 'Return source code of a blueprint',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'id': '3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595',
                                        'source_code': 'def f(arg1: str):\nreturn arg1 + 2',
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
