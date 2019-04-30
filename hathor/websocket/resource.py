import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class WebsocketStatsResource(resource.Resource):
    """ Implements a web server API to return stats from Websocket

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, websocket_factory):
        # Important to have the websocket_factory, so we can have the connections
        self.websocket_factory = websocket_factory

    def render_GET(self, request):
        """ GET request for /websocket_stats/ that returns the stats from Websocket

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {
            'connections': len(self.websocket_factory.connections),
            'addresses': len(self.websocket_factory.address_connections),
        }
        return json.dumps(data, indent=4).encode('utf-8')


WebsocketStatsResource.openapi = {
    '/websocket_stats': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '30r/s',
                }
            ],
            'per-ip': [
                {
                    'rate': '1r/s',
                }
            ]
        },
        'get': {
            'operationId': 'websocket_stats',
            'summary': 'Websocket stats',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'connections': 4,
                                        'addresses': 6,
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
