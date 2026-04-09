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

import enum

from structlog import get_logger

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, set_cors
from hathor.conf.settings import HathorSettings
from hathor.crypto.util import decode_address
from hathor.exception import HathorError
from hathor.manager import HathorManager
from hathor.util import api_catch_exceptions, json_dumpb, json_loadb

logger = get_logger()


class APIError(HathorError):
    """Used for aborting and returning an error with optional status code."""
    status_code: int

    def __init__(self, msg, status_code=400):
        super().__init__(msg)
        self.status_code = status_code


class Capabilities(enum.Enum):
    MERGED_MINING = 'mergedmining'


@register_resource
class GetBlockTemplateResource(Resource):
    """ Resource for generating a Block template for mining.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager, settings: HathorSettings) -> None:
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self._settings = settings
        self.log = logger.new()

    @api_catch_exceptions
    def render_GET(self, request):
        """ GET request for /get_block_template/
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # params
        raw_args = get_args(request)
        raw_address = raw_args.get(b'address')
        if raw_address:
            address = decode_address(raw_address[0].decode())
        else:
            address = b''
        caps = set(map(lambda s: Capabilities(s.decode()), raw_args.get(b'capabilities', [])))
        merged_mining = Capabilities.MERGED_MINING in caps

        if not self.manager.can_start_mining():
            self.log.debug('cannot generate Block Template, node syncing')
            # XXX: HTTP 503 Service Unavailable is suitable for temporary server errors
            raise APIError('Node syncing', 503)

        # get block
        # XXX: miner can edit block data and output_script, so it's fine if address is None
        block = self.manager.generate_mining_block(address=address, merge_mined=merged_mining)
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        block.hash = b'\x00'

        # serialize
        data = block.to_json(include_metadata=True)
        data.pop('hash')
        assert data['metadata']['hash'] == '00'
        data['metadata']['hash'] = None
        data.pop('inputs')
        data.pop('nonce', None)
        data.pop('aux_pow', None)

        return json_dumpb(data)


@register_resource
class SubmitBlockResource(Resource):
    """ Resource for submitting a block mined from a template.

    Although there isn't any requirement that the mined block is generated from the get_block_template, there may be in
    the future. Furthermore there is always a chance that this node doesn't yet have the parent txs if the template was
    generated elsewhere. The only risk is missing the chance to propagate a block that could have been valid.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self.log = logger.new()

    @api_catch_exceptions
    def render_POST(self, request):
        """ POST request for /submit_block/
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = json_loadb(request.content.read())

        tx = self.manager.vertex_parser.deserialize(bytes.fromhex(data['hexdata']), storage=self.manager.tx_storage)

        if not tx.is_block:
            self.log.debug('expected Block, received Transaction', data=data)
            raise APIError('Not a block')

        if not self.manager.can_start_mining():
            self.log.debug('cannot propagate Block, node syncing', data=data)
            raise APIError('Node syncing')

        res = self.manager.submit_block(tx)

        return json_dumpb({'result': res})


GetBlockTemplateResource.openapi = {
    '/get_block_template': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '50r/s',
                }
            ],
            'per-ip': [
                {
                    'rate': '1r/s',
                    'burst': 3,
                    'delay': 3,
                }
            ]
        },
        'get': {
            'tags': ['mining'],
            'operationId': 'get_block_template',
            'summary': 'EXPERIMENTAL: Get parameters for a miner, pool or proxy, to build mining block.',
            'parameters': [
                {
                    'name': 'capabilities',
                    'in': 'query',
                    'description': 'Requested capabilities when generating a block template',
                    'schema': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [i.value for i in Capabilities]
                        }
                    }
                }
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'schema': {
                                'type': 'object',
                                'properties': {
                                    'timestamp': {
                                        'type': 'integer',
                                    },
                                    'version': {
                                        'type': 'integer',
                                    },
                                    'weight': {
                                        'type': 'number',
                                    },
                                    'parents': {
                                        'type': 'array',
                                        'items': {
                                            'type': 'string',
                                        }
                                    },
                                    'outputs': {
                                        'type': 'array',
                                        'items': {
                                            'type': 'object',
                                            'properties': {
                                                'value': {
                                                    'type': 'integer',
                                                },
                                                'token_data': {
                                                    'type': 'integer',
                                                },
                                                'script': {
                                                    'type': 'string',
                                                },
                                            }
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
}


SubmitBlockResource.openapi = {
    '/submit_block': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '50r/s',
                    'burst': 10,
                    'delay': 0,
                }
            ],
            'per-ip': [
                {
                    'rate': '5r/s',
                    'burst': 1,
                    'delay': 0,
                }
            ]
        },
        'post': {
            'tags': ['mining'],
            'operationId': 'submit_block',
            'summary': 'EXPERIMENTAL: Called by a miner to submit a block they found',
            'requestBody': {
                'description': 'Data to be propagated',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'hexdata': {
                                    'type': 'string'
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
                            'schema': {
                                'type': 'object',
                                'properties': {
                                    'result': {
                                        'type': 'bool'
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
