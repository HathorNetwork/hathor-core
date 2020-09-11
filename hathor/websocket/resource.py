from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.websocket.factory import HathorAdminWebsocketFactory


@register_resource
class WebsocketStatsResource(resource.Resource):
    """ Implements a web server API to return stats from Websocket

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, websocket_factory: 'HathorAdminWebsocketFactory'):
        # Important to have the websocket_factory, so we can have the connections
        self.websocket_factory = websocket_factory

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /websocket_stats/ that returns the stats from Websocket

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {
            'connections': len(self.websocket_factory.connections),
            'subscribed_addresses': len(self.websocket_factory.address_connections),
        }
        return json_dumpb(data)


WebsocketStatsResource.openapi = {
    '/websocket_stats': {
        'x-visibility': 'private',
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
