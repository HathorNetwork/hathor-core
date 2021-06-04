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
This modules provides a aiohttp.web.Application that exposes an HTTP DEBUG API that MUST NOT BE PUBLIC.
"""

import asyncio
import cProfile
import logging
import os
import random
import tempfile
import tracemalloc
from typing import Any, Callable, Optional

from aiohttp import web
from aiohttp.abc import AbstractStreamWriter
from structlog import get_logger

from hathor.merged_mining.coordinator import MergedMiningCoordinator, MergedMiningStratumProtocol

logger = get_logger()
routes = web.RouteTableDef()


_MM = 'mm_coord'
_LOG = 'log'
_DEFAULT_TERM_SIZE = (80, 24)


async def make_app(mm_coord: MergedMiningCoordinator) -> web.Application:
    """ Create instance of asyncio.web.Application that serves the status API.
    """
    global routes
    app = web.Application()
    app[_LOG] = logger.new()
    app[_MM] = mm_coord
    app.router.add_routes(routes)
    return app


class TempfileResponse(web.FileResponse):
    """ Deletes (os.unlink) file after sending it, meant to be used with files created with tempfile.mkstemp
    """

    async def prepare(self, request: web.BaseRequest) -> Optional[AbstractStreamWriter]:
        try:
            return await super().prepare(request)
        finally:
            os.unlink(self._path)


@routes.get('/ping')
@routes.post('/ping')
async def ping_pong(_request: web.Request) -> web.StreamResponse:
    """ GET/POST ping to get pong, useful for checking if the API is running and not mistaking it with the status API

    curl -X GET 'localhost:9999/ping' -v
    curl -X POST 'localhost:9999/ping' -v
    """
    return web.Response(text='pong\n')


@routes.post('/logging/debug_on')
async def logging_debug_on(request: web.Request) -> web.StreamResponse:
    """ Change logging level to DEBUG

    Example:

    curl -v -X POST 'localhost:9999/logging/debug_on'
    """
    logging.getLogger().setLevel(logging.DEBUG)
    return web.Response(status=204)


@routes.post('/logging/debug_off')
async def logging_debug_off(request: web.Request) -> web.StreamResponse:
    """ Change logging level to INFO

    Example:

    curl -v -X POST 'localhost:9999/logging/debug_off'
    """
    logging.getLogger().setLevel(logging.INFO)
    return web.Response(status=204)


@routes.post('/pudb/set_trace')
async def pudb_set_trace(request: web.Request) -> web.StreamResponse:
    """ PuDB remote debugging: https://documen.tician.de/pudb/starting.html#remote-debugging

    XXX: weird things can happen, use with caution, and don't rely on leaving the server running after starting pudb

    From their docs:

    > At this point, the debugger will look for a free port and wait for a telnet connection:
    >
    > ```
    > pudb:6899: Please telnet into 127.0.0.1 6899.
    > pudb:6899: Waiting for client...
    > ```

    Use the `term_size` url param for a custom terminal size:

    Example:

    curl -X POST 'localhost:9999/pudb/set_trace?term_size=143x43' -v

    Note: The MergedMiningCoordinator can be accesses through `request.app[_MM]`
    """
    try:
        from pudb.remote import set_trace
    except ImportError:
        return web.Response(status=500, text='pudb not installed\n')
    log = request.app[_LOG]
    term_size = _DEFAULT_TERM_SIZE
    term_size_query = request.query.get('term_size')
    if term_size_query is not None:
        try:
            x, y = term_size_query.split('x')
            term_size = int(x), int(y)
        except ValueError:
            pass
    log.info('set_trace', term_size=term_size)
    set_trace(term_size=term_size)
    return web.Response(status=204)


_tracemalloc_started: bool = False


@routes.post('/tracemalloc/start')
async def tracemalloc_start(request: web.Request) -> web.StreamResponse:
    """ Starts tracemalloc: https://docs.python.org/3/library/tracemalloc.html

    Example:

    curl -v -X POST 'localhost:9999/tracemalloc/start'
    """
    global _tracemalloc_started
    if _tracemalloc_started:
        return web.Response(status=400, text='already started\n')
    log = request.app[_LOG]
    log.info('tracemalloc.start')
    tracemalloc.start()
    _tracemalloc_started = True
    return web.Response(status=204)


@routes.post('/tracemalloc/dump')
async def tracemalloc_dump(request: web.Request) -> web.StreamResponse:
    """ Takes a snapshot and returns the bytes that `Snapshot.dump` would save on a file, which can be loaded later.

    Useful for capturing tracing progressions before the a final stop.

    Example:

    curl -v -X POST 'localhost:9999/tracemalloc/dump'
    curl -v -X POST 'localhost:9999/tracemalloc/dump?download' -o tracemalloc.dump
    """
    global _tracemalloc_started
    if not _tracemalloc_started:
        return web.Response(status=400, text='not started\n')
    log = request.app[_LOG]
    s = tracemalloc.take_snapshot()
    _, f = tempfile.mkstemp()
    log.info('tracemalloc.take_snapshot', tmpfile=f)
    s.dump(f)
    if 'download' in request.query:
        return TempfileResponse(f)
    else:
        return web.Response(text=f + '\n')


@routes.post('/tracemalloc/stop')
async def tracemalloc_stop(request: web.Request) -> web.StreamResponse:
    """ Stops tracemalloc: https://docs.python.org/3/library/tracemalloc.html

    Example:

    curl -v -X POST 'localhost:9999/tracemalloc/stop'
    curl -v -X POST 'localhost:9999/tracemalloc/stop?download' -o tracemalloc.dump
    """
    global _tracemalloc_started
    if not _tracemalloc_started:
        return web.Response(status=400, text='not started\n')
    log = request.app[_LOG]
    s = tracemalloc.take_snapshot()
    tracemalloc.stop()
    _tracemalloc_started = False
    _, f = tempfile.mkstemp()
    log.info('tracemalloc.take_snapshot+stop', tmpfile=f)
    s.dump(f)
    if 'download' in request.query:
        return TempfileResponse(f)
    else:
        return web.Response(text=f + '\n')


@routes.post('/asyncio/count_all')
async def asyncio_count_all(request: web.Request) -> web.StreamResponse:
    """ Counts all tasks on asyncio: `len(asyncio.Task.all_tasks())`

    Example:

    curl -v -X POST 'localhost:9999/asyncio/count_all'
    """
    log = request.app[_LOG]
    log.info('asyncio.Task.all_tasks')
    count = len(asyncio.Task.all_tasks())
    return web.Response(text=str(count) + '\n')


@routes.post('/asyncio/count_running')
async def asyncio_count_running(request: web.Request) -> web.StreamResponse:
    """ Counts running tasks on asyncio: ~`len(t in asyncio.Task.all_tasks() if not t.done)`

    Example:

    curl -v -X POST 'localhost:9999/asyncio/count_running'
    """
    log = request.app[_LOG]
    log.info('asyncio.Task.all_tasks')
    count = sum(1 for t in asyncio.Task.all_tasks() if not t.done())
    return web.Response(text=str(count) + '\n')


_profiler: Optional[cProfile.Profile] = None


@routes.post('/profiler/start')
async def profiler_start(request: web.Request) -> web.StreamResponse:
    """ Starts cProfile profiler: https://docs.python.org/3/library/profile.html#module-cProfile

    Example:

    curl -v -X POST 'localhost:9999/profiler/start'
    """
    global _profiler
    if _profiler is not None:
        return web.Response(status=400, text='already started\n')
    log = request.app[_LOG]
    log.info('cProfile.Profile')
    _profiler = cProfile.Profile()
    _profiler.enable()
    return web.Response(status=204)


@routes.post('/profiler/stop')
async def profiler_stop(request: web.Request) -> web.StreamResponse:
    """ Stops cProfile profiler: https://docs.python.org/3/library/profile.html#module-cProfile

    Example:

    curl -v -X POST 'localhost:9999/profiler/stop'
    curl -v -X POST 'localhost:9999/profiler/stop?download' -o profiler.dump
    """
    global _profiler
    if _profiler is None:
        return web.Response(status=400, text='not started\n')
    _profiler.disable()
    log = request.app[_LOG]
    _, f = tempfile.mkstemp()
    log.info('profiler.dump_stats', tmpfile=f)
    _profiler.dump_stats(f)
    _profiler = None
    if 'download' in request.query:
        return TempfileResponse(f)
    else:
        return web.Response(text=f + '\n')


_tracker: Optional[Any] = None  # XXX: type erased to make it easy on pympler being an optional dep


@routes.post('/pympler/tracker/start')
async def pympler_tracker_start(request: web.Request) -> web.StreamResponse:
    """ Starts Pympler tracker: https://pympler.readthedocs.io/en/latest/

    Example:

    curl -v -X POST 'localhost:9999/pympler/tracker/start'
    """
    global _tracker
    try:
        from pympler import tracker
    except ImportError:
        return web.Response(status=500, text='pympler not installed\n')
    if _tracker is not None:
        return web.Response(status=400, text='already started\n')
    log = request.app[_LOG]
    log.info('pympler.tracker.SummaryTracker')
    _tracker = tracker.SummaryTracker()
    return web.Response(status=204)


@routes.post('/pympler/tracker/diff')
async def pympler_tracker_diff(request: web.Request) -> web.StreamResponse:
    """ Get Pympler tracker diff: https://pympler.readthedocs.io/en/latest/

    Example:

    curl -v -X POST 'localhost:9999/pympler/tracker/diff'
    curl -v -X POST 'localhost:9999/pympler/tracker/diff?print'
    """
    global _tracker
    if _tracker is None:
        return web.Response(status=400, text='not started\n')
    log = request.app[_LOG]
    if 'print' in request.query:
        log.info('tracker.print_diff')
        _tracker.print_diff()
        return web.Response(status=204)
    else:
        log.info('tracker.diff')
        return web.json_response(_tracker.diff())


@routes.post('/pympler/tracker/stop')
async def pympler_tracker_stop(request: web.Request) -> web.StreamResponse:
    """ Stops Pympler tracker: https://pympler.readthedocs.io/en/latest/

    Example:

    curl -v -X POST 'localhost:9999/pympler/tracker/stop'
    """
    global _tracker
    if _tracker is None:
        return web.Response(status=400, text='not started\n')
    _tracker = None
    log = request.app[_LOG]
    log.info('del tracker')
    return web.Response(status=204)


@routes.post('/pympler/summary')
async def pympler_summary(request: web.Request) -> web.StreamResponse:
    """ Build and return a Pympler summary: https://pympler.readthedocs.io/en/latest/muppy.html#the-summary-module

    Example:

    curl -v -X POST 'localhost:9999/pympler/summary'
    """
    try:
        from pympler import muppy, summary
    except ImportError:
        return web.Response(status=500, text='pympler not installed\n')
    log = request.app[_LOG]
    all_objects = muppy.get_objects()
    sum_ = summary.summarize(all_objects)
    if 'print' in request.query:
        log.info('pympler.summary.print')
        summary.print_(sum_)
        return web.Response(status=204)
    else:
        log.info('pympler.summary')
        return web.json_response(sum_)


def _kill_filter(mm: MergedMiningCoordinator, filter_fn: Callable[[MergedMiningStratumProtocol], bool]) -> int:
    """ Kill all workers that the filter `fltr` returns true for.
    """
    count = 0
    for protocol in filter(filter_fn,  mm.miner_protocols.values()):
        count += 1
        protocol.transport.abort()
    return count


@routes.post('/mm/killall')
async def mm_killall(request: web.Request) -> web.StreamResponse:
    """ Kill all workers connected to the MM server, returns kill  count

    Example:

    curl -v -X POST 'localhost:9999/mm/killall'
    """
    log = request.app[_LOG]
    log.info('mm.killall')
    mm = request.app[_MM]
    count = _kill_filter(mm, lambda _: True)
    return web.Response(text=str(count) + '\n')


@routes.post('/mm/kill/by-id/{id}')
async def mm_kill_byid(request: web.Request) -> web.StreamResponse:
    """ Kill the worker with given miner id.

    Example:

    curl -v -X POST 'localhost:9999/mm/kill/by-id/1234'
    """
    log = request.app[_LOG]
    target_id = request.match_info['id']
    log.info('mm.kill.byid', target_id=target_id)
    mm = request.app[_MM]

    def id_filter(protocol):
        return protocol.miner_id == target_id
    count = _kill_filter(mm, id_filter)

    return web.Response(text=str(count) + '\n')


@routes.post('/mm/kill/by-name/{name}')
async def mm_kill_byname(request: web.Request) -> web.StreamResponse:
    """ Kill all workers that have the given worker name

    Example:

    curl -v -X POST 'localhost:9999/mm/kill/by-name/foobar'
    """
    log = request.app[_LOG]
    target_name = request.match_info['name']
    if target_name is None:
        return web.Response(status=400, text='expected a name\n')
    log.info('mm.kill.byname', target_name=target_name)
    mm = request.app[_MM]

    def name_filter(protocol):
        return protocol.worker_name == target_name
    count = _kill_filter(mm, name_filter)

    return web.Response(text=str(count) + '\n')


@routes.post('/mm/kill/random/{probability}')
async def mm_kill_random(request: web.Request) -> web.StreamResponse:
    """ Kill workers randomly with the given probability (between 0 and 1)

    Example:

    curl -v -X POST 'localhost:9999/mm/kill/random/.5'
    """
    log = request.app[_LOG]
    p = float(request.match_info['probability'])
    if p < 0 or p > 1:
        return web.Response(status=400, text=f'expected 0 <= p <= 1, got p={p}\n')
    log.info('mm.kill.random', probability=p)
    mm = request.app[_MM]

    def random_filter(protocol):
        return random.random() < p
    count = _kill_filter(mm, random_filter)

    return web.Response(text=str(count) + '\n')
