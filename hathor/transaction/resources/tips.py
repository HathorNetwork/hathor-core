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

import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class TipsResource(resource.Resource):
    """ Implements a web server API to return the tips
        Returns a list of tips hashes

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request to /tips/ that return a list of tips hashes

            'timestamp' is an optional parameter to be used in the get_tx_tips method

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        timestamp = None
        if b'timestamp' in request.args:
            try:
                timestamp = int(request.args[b'timestamp'][0])
            except ValueError:
                return json.dumps({
                    'success': False,
                    'message': 'Invalid timestamp parameter, expecting an integer'
                }).encode('utf-8')

        tx_tips = self.manager.tx_storage.get_tx_tips(timestamp)
        ret = {'success': True, 'tips': [tip.data.hex() for tip in tx_tips]}
        return json.dumps(ret).encode('utf-8')


TipsResource.openapi = {
    '/tips': {
        'x-visibility': 'private',
        'get': {
            'tags': ['transaction'],
            'operationId': 'tips',
            'summary': 'Tips',
            'description': 'Returns a list of tips hashes in hexadecimal',
            'parameters': [
                {
                    'name': 'timestamp',
                    'in': 'query',
                    'description': 'Timestamp to search for the tips',
                    'required': False,
                    'schema': {
                        'type': 'int'
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
                                        'tips': [
                                            '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            '0002bb171de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c2'
                                        ]
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid timestamp parameter',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid timestamp parameter, expecting an integer'
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
