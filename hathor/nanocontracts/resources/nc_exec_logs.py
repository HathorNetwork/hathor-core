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

from typing import Any

from pydantic import Field
from twisted.web.http import Request

from hathor.api_util import Resource
from hathor.cli.openapi_files.register import register_resource
from hathor.utils.api import QueryParams


@register_resource
class NCExecLogsResource(Resource):
    """Implements a web server GET API to get nano contract execution logs."""
    isLeaf = True

    def render_GET(self, request: Request) -> bytes:
        raise NotImplementedError('temporarily removed during nano merge')


class NCExecLogsParams(QueryParams):
    id: str
    log_level: str | None = None
    all_execs: bool = False


class NCExecLogsResponse(QueryParams):
    success: bool = Field(const=True, default=True)
    nc_id: str
    nc_execution: str | None
    logs: dict[str, Any]


NCExecLogsResource.openapi = {
    '/nano_contract/logs': {
        'x-visibility': 'private',
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
