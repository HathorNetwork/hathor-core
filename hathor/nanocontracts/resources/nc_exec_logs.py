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

from typing import Any, Literal

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.manager import HathorManager
from hathor.nanocontracts.nc_exec_logs import NCLogLevel
from hathor.transaction import Transaction
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.utils.api import ErrorResponse, QueryParams, Response


@register_resource
class NCExecLogsResource(Resource):
    """Implements a web server GET API to get nano contract execution logs."""
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager
        self.nc_log_storage = manager.consensus_algorithm.block_algorithm_factory.nc_log_storage

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if self.nc_log_storage is None:
            request.setResponseCode(503)
            error_response = ErrorResponse(success=False, error='Nano contract exec logs not initialized')
            return error_response.json_dumpb()

        params = NCExecLogsParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        try:
            nc_id_bytes = bytes.fromhex(params.id)
        except ValueError:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error=f'Invalid id: {params.id}')
            return error_response.json_dumpb()

        try:
            nc = self.manager.tx_storage.get_transaction(nc_id_bytes)
        except TransactionDoesNotExist:
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error=f'NC "{params.id}" not found.')
            return error_response.json_dumpb()

        if not nc.is_nano_contract():
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error=f'NC "{params.id}" not found.')
            return error_response.json_dumpb()

        log_level: NCLogLevel = NCLogLevel.DEBUG
        if params.log_level is not None:
            params_log_level = NCLogLevel.from_str(params.log_level)
            if not params_log_level:
                request.setResponseCode(400)
                error_response = ErrorResponse(success=False, error=f'Invalid log level: {params.log_level}')
                return error_response.json_dumpb()
            log_level = params_log_level

        meta = nc.get_metadata()
        logs = self.nc_log_storage.get_json_logs(
            nc.hash,
            log_level=log_level,
            block_id=None if params.all_execs else meta.first_block,
        )

        if logs is None:
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error='No logs were found.')
            return error_response.json_dumpb()

        assert isinstance(nc, Transaction)
        nano_header = nc.get_nano_header()

        response = NCExecLogsResponse(
            logs=logs,
            nc_id=nano_header.get_contract_id().hex(),
            nc_execution=meta.nc_execution,
        )
        return response.json_dumpb()


class NCExecLogsParams(QueryParams):
    id: str
    log_level: str | None = None
    all_execs: bool = False


class NCExecLogsResponse(Response):
    success: Literal[True] = True
    nc_id: str
    nc_execution: str | None
    logs: dict[str, Any]


NCExecLogsResource.openapi = {
    '/nano_contract/logs': {
        'x-visibility': 'private',
        'x-visibility-override': {
            'nano-testnet-bravo': 'public',
            'hathor-testnet-india': 'public',
            'hathor-testnet-playground': 'public',
        },
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
            'operationId': 'nano_contracts_logs',
            'summary': 'Get execution logs of a nano contract',
            'description': 'Returns the execution logs of a nano contract per Block ID that executed it.',
            'parameters': [
                {
                    'name': 'id',
                    'in': 'query',
                    'description': 'ID of the nano contract to get the logs from.',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'log_level',
                    'in': 'query',
                    'description': 'Minimum log level to filter logs. One of DEBUG, INFO, WARN, ERROR. '
                                   'Default is DEBUG, that is, no filter.',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'all_execs',
                    'in': 'query',
                    'description': 'Whether to get all NC executions or just from the current block that executed the '
                                   'NC, that is, the NC\'s first_block. Default is false.',
                    'required': False,
                    'schema': {
                        'type': 'bool'
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
                                    'summary': 'NC execution logs',
                                    'value': {
                                        'success': True,
                                        'logs': {
                                            '25b90432c597f715e4ad4bd62436ae5f48dc988d47f051d8b3eb21ca008d6783': [
                                                {
                                                    'error_traceback': None,
                                                    'timestamp': 1739289130,
                                                    'logs': [
                                                        {
                                                            'type': 'BEGIN',
                                                            'level': 'DEBUG',
                                                            'nc_id': '00001cc24fc57fce28da879c24d46d84'
                                                                     '1c932c04bdadac28f0cd530c6c702dc9',
                                                            'call_type': 'public',
                                                            'method_name': 'initialize',
                                                            'args': [],
                                                            'kwargs': {},
                                                            'timestamp': 1739289133,
                                                        },
                                                        {
                                                            'type': 'LOG',
                                                            'level': 'INFO',
                                                            'message': 'initialize() called on MyBlueprint1',
                                                            'key_values': {}
                                                        }
                                                    ],
                                                }
                                            ],
                                        },
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
