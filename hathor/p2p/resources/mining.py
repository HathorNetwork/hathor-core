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

import base64
import binascii
import struct
from json import JSONDecodeError

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args
from hathor.crypto.util import decode_address
from hathor.transaction.vertex_parser import vertex_deserializer
from hathor.util import json_dumpb, json_loadb
from hathor.wallet.exceptions import InvalidAddress

# TODO: deprecate these calls to eventually remove them on v2


@register_resource
class MiningResource(Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request: Request) -> bytes:
        """ POST request /mining/
            Expects a parameter 'block_bytes' that is the block in bytes
            Create the block object from the bytes and propagate it

            :rtype: bytes
        """
        if request.content is None:
            return b'0'
        raw_data = request.content.read()
        if raw_data is None:
            return b'0'
        try:
            post_data = json_loadb(raw_data)
            block_bytes_str = post_data['block_bytes']
            block_bytes = base64.b64decode(block_bytes_str)
            block = vertex_deserializer.deserialize(block_bytes, storage=self.manager.tx_storage)
        except (AttributeError, KeyError, ValueError, JSONDecodeError, binascii.Error, struct.error):
            # XXX ideally, we should catch each error separately and send an specific error
            # message, but we only return 0 or 1 on the API
            # AttributeError, JSONDecodeError: empty data or error decoding json
            # KeyError: missing 'block_bytes' on post_data
            # ValueError, struct.error: raised in create_block_from_struct
            # binascii.Error: incorrect base64 data
            return b'0'

        ret = self.manager.submit_block(block)
        if ret:
            return b'1'
        return b'0'

    def render_GET(self, request):
        """ GET request /mining/
            Generates a new block to be mined with correct parents
            Returns a json with a list of parents hash and the block in bytes

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')

        if not self.manager.can_start_mining():
            request.setResponseCode(503)
            return json_dumpb({'reason': 'Node still syncing'})

        address = None

        raw_args = get_args(request)
        if b'address' in raw_args:
            address_txt = raw_args[b'address'][0].decode('utf-8')
            try:
                address = decode_address(address_txt)  # bytes
            except InvalidAddress:
                return json_dumpb({'success': False, 'message': 'Invalid address'})

        block = self.manager.generate_mining_block(address=address)
        block_bytes = block.get_struct()

        data = {
            'parents': [x.hex() for x in block.parents],
            'block_bytes': base64.b64encode(block_bytes).decode('utf-8'),
        }
        return json_dumpb(data)


MiningResource.openapi = {
    '/mining': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '200r/s',
                    'burst': 200,
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
            'tags': ['p2p'],
            'operationId': 'mining_get',
            'summary': 'Block to be mined',
            'description': ('Returns the base64 of the block to be mined in'
                            'bytes and an array of the hash of parents in hex'),
            'parameters': [
                {
                    'name': 'address',
                    'in': 'query',
                    'description': 'Address to send the mined tokens',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
            ],
            'responses': {
                '503': {
                    'description': 'Node still syncing',
                    'content': {
                        'application/json': {
                            'examples': {
                                'error': {
                                    'summary': 'Node still syncing',
                                    'value': {
                                        'reason': 'Node still syncing'
                                    }
                                }
                            }
                        },
                    }
                },
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Block in bytes and array with hash of parents in hex',
                                    'value': {
                                        'parents': [
                                            '0001e298570e37d46f9101bcf903bde67186f26a83d88b9cb196f38b49623457',
                                            '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            '0002bb171de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c2'
                                        ],
                                        'block_bytes': ('AAFALAAAAAAAAFw3hyYAAAAAAAAAAgAAAAEAAwAAAeKYVw431G+RA'
                                                        'bz5A73mcYbyaoPYi5yxlvOLSWI0VwAAKzvk44duZ7XgkNdtzXHN4a'
                                                        'MMoeVOONZXF7oTHNIvAAK7Fx3jSQgoAo7F7vMyWVastrz/pqUEZru'
                                                        'agdODY8IAAAfQAAAZdqkUjb8SxMLMIljwVbjaYSHUbiVSjt6IrAAAAAA=')
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        'post': {
            'tags': ['p2p'],
            'operationId': 'mining_post',
            'summary': 'Propagate a mined block',
            'description': 'Propagate to the Hathor network a complete block after the proof-of-work',
            'requestBody': {
                'description': 'Data to be propagated',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/MinedBlock'
                            },
                        'examples': {
                            'mined_block': {
                                'summary': 'Mined block',
                                'value': {
                                    'block_bytes': ('AAFALAAAAAAAAFw3iaUAAAAAAAAAAgAAAAEAAwAAAeKYVw431G+RAbz5A73m'
                                                    'cYbyaoPYi5yxlvOLSWI0VwAAKzvk44duZ7XgkNdtzXHN4aMMoeVOONZXF7oT'
                                                    'HNIvAAK7Fx3jSQgoAo7F7vMyWVastrz/pqUEZruagdODY8IAAAfQAAAZdqkU'
                                                    '0AoLEAX+1b36s+VyaMc9bkj/5byIrAAAEa8=')
                                }
                            }
                        }
                    }
                }
            },
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': '1',
                                'error': '0'
                            }
                        }
                    }
                }
            }
        }
    }
}
