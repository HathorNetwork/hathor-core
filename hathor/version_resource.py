import json

from twisted.web import resource

import hathor
from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


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
            'network': self.manager.network,
            'min_weight': self.manager.min_tx_weight,  # DEPRECATED
            'min_tx_weight': self.manager.min_tx_weight,
            'min_tx_weight_coefficient': self.manager.min_tx_weight_coefficient,
            'min_tx_weight_k': self.manager.min_tx_weight_k,
        }
        return json.dumps(data, indent=4).encode('utf-8')


VersionResource.openapi = {
    '/version': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '360r/s',
                    'burst': 360,
                    'delay': 180
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
                                        'version': '0.16.0-beta',
                                        'network': 'testnet-bravo',
                                        'min_weight': 14,
                                        'min_tx_weight': 14,
                                        'min_tx_weight_coefficient': 1.6,
                                        'min_tx_weight_k': 100,
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
