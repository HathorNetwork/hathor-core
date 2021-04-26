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

from typing import TYPE_CHECKING

from twisted.web import server

from hathor.profiler import get_cpu_profiler

if TYPE_CHECKING:
    from twisted.web.http import Request

cpu = get_cpu_profiler()


class SiteProfiler(server.Site):
    def _get_profiler_key(self, request: 'Request') -> str:
        addr = request.getClientAddress()
        parts = [request.path.decode(), getattr(addr, 'host', '-')]
        key = 'http-api!' + ':'.join(parts)
        return key

    def _get_client_ip(self, request: 'Request') -> str:
        x_real_ip = request.getHeader('X-Real-IP')
        if x_real_ip:
            return x_real_ip.strip()
        x_forwarded_for = request.getHeader('X-Forwarded-For')
        if x_forwarded_for:
            return x_forwarded_for.split(',', 1)[0].strip()
        addr = request.getClientAddress()
        return getattr(addr, 'host', 'unknown')

    @cpu.profiler('http-api')
    @cpu.profiler(key=lambda self, request: request.path.decode())
    @cpu.profiler(key=lambda self, request: self._get_client_ip(request))
    def getResourceFor(self, request):
        return super().getResourceFor(request)
