import json

from twisted.web import resource

import hathor
from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.constants import MIN_TX_WEIGHT


@register_resource
class VersionResource(resource.Resource):
    """ Implements a web server API with POST to return the api version and some configuration

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can have access to min_tx_weight_coefficient
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /version/ that returns the API version

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {
            'version': hathor.__version__,
            'min_weight': MIN_TX_WEIGHT,
            'min_tx_weight_coefficient': self.manager.min_tx_weight_coefficient
        }
        return json.dumps(data, indent=4).encode('utf-8')


VersionResource.openapi = {
    '/version': {
        'get': {
            'operationId': 'version',
            'summary': 'Hathor version',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'version': '0.16.0-beta'
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
