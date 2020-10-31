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

"""
This modules provides a aiohttp.web.Application that exposes an HTTP/WS status.
"""

import asyncio

from aiohttp import WSCloseCode, web
from structlog import get_logger

from hathor.merged_mining.coordinator import MergedMiningCoordinator

logger = get_logger()
routes = web.RouteTableDef()


_LOG = 'log'
_MM = 'mm_coord'
_WS = 'websockets'


async def make_app(mm_coord: MergedMiningCoordinator) -> web.Application:
    """ Create instance of asyncio.web.Application that serves the status API.
    """
    global routes
    app = web.Application()
    app[_LOG] = logger.new()
    app[_MM] = mm_coord
    app[_WS] = []  # websocket handlers should add/remove connections here
    app.router.add_routes(routes)
    app.on_shutdown.append(_close_websockets)
    return app


async def _close_websockets(app: web.Application) -> None:
    """ Internal function for closing websockets when application is shutting down.
    """
    for ws in app[_WS]:
        await ws.close(code=WSCloseCode.GOING_AWAY, message='Server shutdown')


@routes.get('/status')
async def get_status(request: web.Request) -> web.Response:
    """ GET JSON endpoint for returning the current status.
    """
    status = request.app[_MM].status()
    return web.json_response(status)


@routes.get('/status_ws')
async def get_status_ws(request: web.Request) -> web.WebSocketResponse:
    """ WS endpoint for getting periodic status, messages are in JSON with the same format as `get_status`.
    """
    log = request.app[_LOG]
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    request.app[_WS].append(ws)
    try:
        while True:
            status = request.app[_MM].status()
            await ws.send_json(status)
            await asyncio.sleep(1)  # 1 second
    except Exception:
        log.exception('could not to send ws message, closing ws connection')
        await ws.close()
    finally:
        request.app[_WS].remove(ws)
    return ws


@routes.get('/health_check')
async def get_health_check(request: web.Request) -> web.Response:
    """ GET JSON endpoint for returning the current status.
    """
    return web.Response(status=204)
