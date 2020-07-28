from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import parse_get_arguments, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager

ARGS = ['begin', 'end']


@register_resource
class TipsHistogramResource(resource.Resource):
    """ Implements a web server API to return the tips in a timestamp interval.
        Returns a list of timestamps and numbers of tips.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ Get request to /tips-histogram/ that return the number of tips between two timestamp
            We expect two GET parameters: 'begin' and 'end'

            'begin': int that indicates the beginning of the interval
            'end': int that indicates the end of the interval

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        parsed = parse_get_arguments(request.args, ARGS)
        if not parsed['success']:
            return json_dumpb({
                'success': False,
                'message': 'Missing parameter: {}'.format(parsed['missing'])
            })

        args = parsed['args']

        # Get quantity for each
        try:
            begin = int(args['begin'])
        except ValueError:
            return json_dumpb({
                'success': False,
                'message': 'Invalid parameter, cannot convert to int: begin'
            })

        try:
            end = int(args['end'])
        except ValueError:
            return json_dumpb({
                'success': False,
                'message': 'Invalid parameter, cannot convert to int: end'
            })

        v = []
        for timestamp in range(begin, end + 1):
            tx_tips = self.manager.tx_storage.get_tx_tips(timestamp)
            v.append((timestamp, len(tx_tips)))

        return json_dumpb({'success': True, 'tips': v})


TipsHistogramResource.openapi = {
    '/tips-histogram': {
        'x-visibility': 'private',
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
                                },
                                'error': {
                                    'summary': 'Invalid parameter',
                                    'value': {
                                        'success': False,
                                        'message': 'Missing parameter: begin'
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
