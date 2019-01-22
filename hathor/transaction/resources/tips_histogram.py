import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class TipsHistogramResource(resource.Resource):
    """ Implements a web server API to return the tips in a timestamp interval.
        Returns a list of timestamps and numbers of tips.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request to /tips-histogram/ that return the number of tips between two timestamp
            We expect two GET parameters: 'begin' and 'end'

            'begin': int that indicates the beginning of the interval
            'end': int that indicates the end of the interval

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # Get quantity for each
        begin = int(request.args[b'begin'][0])
        end = int(request.args[b'end'][0])

        v = []
        for timestamp in range(begin, end + 1):
            tx_tips = self.manager.tx_storage.get_tx_tips(timestamp)
            v.append((timestamp, len(tx_tips)))

        return json.dumps(v).encode('utf-8')


TipsHistogramResource.openapi = {
    '/tips-histogram': {
        'get': {
            'tags': ['transaction'],
            'operationId': 'tips_histogram',
            'summary': 'Histogram of tips',
            'description': ('Returns a list of tuples (timestamp, quantity)'
                            'for each timestamp in the requested interval'),
            'parameters': [
                {
                    'name': 'begin',
                    'in': 'query',
                    'description': 'Beggining of the timestamp interval',
                    'required': True,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'end',
                    'in': 'query',
                    'description': 'End of the timestamp interval',
                    'required': True,
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
                                        [
                                            1547163020,
                                            1
                                        ],
                                        [
                                            1547163021,
                                            4
                                        ],
                                        [
                                            1547163022,
                                            2
                                        ]
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
