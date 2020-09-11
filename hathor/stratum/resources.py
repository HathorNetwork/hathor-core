from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.manager import HathorManager
from hathor.util import json_dumpb


@register_resource
class MiningStatsResource(resource.Resource):
    """ Implements a web server API to return an unused address of the wallet.

    You must run with option `--status <PORT>`.
    You must run with option `--stratum <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /miners/
            Returns statistics about connected miners

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.stratum_factory:
            request.setResponseCode(503)
            return json_dumpb({'success': False})

        return json_dumpb(self.manager.stratum_factory.get_stats_resource())


MiningStatsResource.openapi = {
    '/miners': {
        'x-visibility': 'private',
        'get': {
            'operationId': 'miners',
            'summary': 'Mining Statistics',
            'description': 'Returns information about each miner connected to the current node',
            'parameters': [],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': [
                                    {
                                        'address': '127.0.0.1:39182',
                                        'blocks_found': 2,
                                        'completed_jobs': 13,
                                        'connection_start_time': 1557834759,
                                        'estimated_hash_rate': 19.2314,
                                        'miner_id': '1b332d80753e4288a9906d3eb258f318'
                                    },
                                    {
                                        'address': '134.182.2.57:5328',
                                        'blocks_found': 7,
                                        'completed_jobs': 17,
                                        'connection_start_time': 1557834861,
                                        'estimated_hash_rate': 24.1923,
                                        'miner_id': '052c48854f1a4fddb902678304ac4864'
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }
    }
}
