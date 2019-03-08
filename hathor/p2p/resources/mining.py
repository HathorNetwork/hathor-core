import base64
import json

from twisted.web import resource

from hathor.cli.openapi_files.register import register_resource
from hathor.transaction import Block


@register_resource
class MiningResource(resource.Resource):
    """ Implements an status web server API, which responds with a summary
    of the node state.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ POST request /mining/
            Expects a parameter 'block_bytes' that is the block in bytes
            Create the block object from the bytes and propagate it

            :rtype: bytes
        """
        post_data = json.loads(request.content.read().decode('utf-8'))
        block_bytes_str = post_data['block_bytes']
        block_bytes = base64.b64decode(block_bytes_str)
        block = Block.create_from_struct(block_bytes, storage=self.manager.tx_storage)
        ret = self.manager.propagate_tx(block)
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
            return json.dumps({'reason': 'Node still syncing'}).encode('utf-8')

        block = self.manager.generate_mining_block()
        block_bytes = block.get_struct()

        data = {
            'parents': [x.hex() for x in block.parents],
            'block_bytes': base64.b64encode(block_bytes).decode('utf-8'),
        }
        return json.dumps(data, indent=4).encode('utf-8')


MiningResource.openapi = {
    '/mining': {
        'get': {
            'tags': ['p2p'],
            'operationId': 'mining_get',
            'summary': 'Block to be mined',
            'description': ('Returns the base64 of the block to be mined in'
                            'bytes and an array of the hash of parents in hex'),
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
