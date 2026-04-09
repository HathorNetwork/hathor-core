# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
from typing import TYPE_CHECKING

from twisted.web.http import Request

import hathor
from hathor._openapi.register import register_resource
from hathor.api_util import Resource, render_options, set_cors
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.profiler import SimpleCPUProfiler


@register_resource
class CPUProfilerResource(Resource):
    """API for top profiler."""
    isLeaf = True

    def __init__(self, manager: 'HathorManager', cpu: 'SimpleCPUProfiler') -> None:
        self.manager = manager
        self.cpu = cpu

    def send_error_message(self, request, message):
        request.setResponseCode(400)
        return {'success': False, 'message': message}

    def render_POST(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        cmd = request.content.read()
        cmd = cmd.decode('utf-8')

        if cmd == 'start':
            if self.cpu.enabled:
                request.setResponseCode(400)
                ret = {'success': False, 'message': 'profiler is already running'}
            else:
                self.cpu.start()
                ret = {'success': True, 'message': 'profiler has been started'}

        elif cmd == 'stop':
            if not self.cpu.enabled:
                request.setResponseCode(400)
                ret = {'success': False, 'message': 'profiler is already stopped'}
            else:
                self.cpu.stop()
                ret = {'success': True, 'message': 'profiler has been stopped'}

        elif cmd == 'reset':
            self.cpu.reset()
            ret = {'success': True, 'message': 'profiler has been reseted'}

        else:
            request.setResponseCode(400)
            ret = {'success': False, 'message': 'invalid command'}

        return json_dumpb(ret)

    def render_GET(self, request):
        v = []
        for key, proc in self.cpu.get_proc_list():
            v.append((key, {
                'percent_cpu': proc.percent_cpu,
                'total_time': proc.total_time,
            }))

        hostname = socket.gethostname()

        ret = {
            'version': hathor.__version__,
            'network': self.manager.network,
            'hostname': hostname,
            'enabled': self.cpu.enabled,
            'last_update': self.cpu.last_update,
            'error': self.cpu.error,
            'proc_list': v,
        }

        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')
        return json_dumpb(ret)

    def render_OPTIONS(self, request: Request) -> int:
        return render_options(request)


CPUProfilerResource.openapi = {
    '/top': {
        'x-visibility': 'private',
        'get': {
            'operationId': 'cpu-profiler',
            'summary': 'Get process data for top command.',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        "enabled": True,
                                        "last_update": 1619215625.833846,
                                        "error": "",
                                        "proc_list": [
                                            [
                                                ["profiler"],
                                                {
                                                    "percent_cpu": 2.679275019698697,
                                                    "total_time": 0.00018599999999990846
                                                }
                                            ], [
                                                ["http-api!/v1a/top/:127.0.0.1"],
                                                {
                                                    "percent_cpu": 0.0,
                                                    "total_time": 4.799999999993698e-05
                                                }
                                            ]
                                        ]
                                    }
                                },
                            },
                        }
                    }
                }
            }
        }
    }
}
