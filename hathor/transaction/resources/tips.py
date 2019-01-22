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

            'timestamp' is an optional expected parameter to be used in the get_tx_tips method

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        timestamp = None
        if b'timestamp' in request.args:
            timestamp = int(request.args[b'timestamp'][0])

        tx_tips = self.manager.tx_storage.get_tx_tips(timestamp)
        ret = [tip.data.hex() for tip in tx_tips]
        return json.dumps(ret).encode('utf-8')


TipsResource.openapi = {
    '/tips': {
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
                                    'value': [
                                        '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                        '0002bb171de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c2'
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
