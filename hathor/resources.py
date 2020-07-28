import os
from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import json_dumpb, json_loadb

if TYPE_CHECKING:
    from hathor.manager import HathorManager


@register_resource
class ProfilerResource(resource.Resource):
    """ Implements a web server API with POST to start a profiler

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager') -> None:
        # Important to have the manager so we can know the wallet
        self.manager = manager

    def gen_dump_filename(self):
        for i in range(1, 100):
            dump_filename = 'profiles/profile{:03d}.prof'.format(i)
            if not os.path.exists(dump_filename):
                return dump_filename
        else:
            raise Exception('Unable to generate dump filename')

    def render_POST(self, request: Request) -> bytes:
        """ POST request for /profiler/

        We expect 'start' or 'stop' as request args and, in the case of stop, also an optional parameter 'filepath'
        'start': bool to represent it should start the profiler
        'stop': bool to represent it should stop the profiler
        'filepath': str of the file path where to save the profiler file
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        data_read = request.content.read()
        post_data = json_loadb(data_read) if data_read else {}
        ret = {'success': True}

        if 'start' in post_data:
            self.manager.start_profiler()

        elif 'stop' in post_data:
            if 'filepath' in post_data:
                filepath = post_data['filepath']
            else:
                filepath = self.gen_dump_filename()

            self.manager.stop_profiler(save_to=filepath)
            ret['saved_to'] = filepath

        else:
            ret['success'] = False

        return json_dumpb(ret)

    def render_OPTIONS(self, request: Request) -> int:
        return render_options(request)


ProfilerResource.openapi = {
    '/profiler': {
        'x-visibility': 'private',
        'post': {
            'operationId': 'profiler',
            'summary': 'Run full node profiler',
            'requestBody': {
                'description': 'Profiler data',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ProfilerPOST'
                        },
                        'examples': {
                            'start': {
                                'summary': 'Start profiler',
                                'value': {
                                    'start': True
                                }
                            },
                            'stop': {
                                'summary': 'Stop profiler',
                                'value': {
                                    'stop': True,
                                    'filepath': 'filepath'
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
                                'success_start': {
                                    'summary': 'Success start',
                                    'value': {
                                        'success': True
                                    }
                                },
                                'success_stop': {
                                    'summary': 'Success stop',
                                    'value': {
                                        'success': True,
                                        'saved_to': 'filepath'
                                    }
                                },
                                'error': {
                                    'summary': 'Error',
                                    'value': {
                                        'success': False
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
