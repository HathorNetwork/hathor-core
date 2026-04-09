# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, render_options, set_cors
from hathor.manager import HathorManager
from hathor.util import json_dumpb, json_loadb


@register_resource
class ProfilerResource(Resource):
    """ Implements a web server API with POST to start a profiler

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        # Important to have the manager so we can know the wallet
        self.manager = manager

    def gen_dump_filename(self):
        for i in range(1, 100):
            dump_filename = 'profiles/profile{:03d}.prof'.format(i)
            if not os.path.exists(dump_filename):
                return dump_filename
        else:
            raise Exception('Unable to generate dump filename')

    def render_POST(self, request):
        """ POST request for /profiler/
            We expect 'start' or 'stop' as request args and, in the case of stop, also an optional parameter 'filepath'
            'start': bool to represent it should start the profiler
            'stop': bool to represent it should stop the profiler
            'filepath': str of the file path where to save the profiler file

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        data_read = request.content.read()
        post_data = json_loadb(data_read) if data_read else {}
        ret = {'success': True}

        if 'start' in post_data:
            reset = False
            if 'reset' in post_data:
                reset = True
            self.manager.start_profiler(reset=reset)

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
                            'start-reset': {
                                'summary': 'Start profiler',
                                'value': {
                                    'start': True,
                                    'reset': True
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
