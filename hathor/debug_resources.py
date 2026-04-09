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
import sys

from structlog import get_logger
from twisted.internet import defer
from twisted.internet.interfaces import IReactorFromThreads
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_arg_default, get_args
from hathor.exception import HathorError
from hathor.manager import HathorManager
from hathor.reactor import ReactorProtocol
from hathor.utils.zope import asserted_cast

logger = get_logger()


# XXX: this class must not inherit from Exception or its sub-classes so it purposely skips any `except Exception`
class DebugException(BaseException):
    pass


@register_resource
class DebugRaiseResource(Resource):
    isLeaf = True
    openapi = {
        '/_debug/raise': {
            'x-visibility': 'private',
            'get': {
                'operationId': 'debug_raise_exception',
                'summary': 'Used for forcing an internal exception. (has no side-effects)',
            }
        }
    }
    exc_class_map = {
        'debug': DebugException,
        'normal': Exception,
        'hathor': HathorError,
    }
    default_msg = 'exception raised for debugging purposes'

    def __init__(self, reactor: ReactorProtocol) -> None:
        super().__init__()
        self._reactor = reactor

    def run(self, exc_cls: type[BaseException], msg: str) -> None:
        raise exc_cls(msg)

    def render_GET(self, request: Request) -> bytes:
        raw_args = get_args(request)
        exc_cls_name = get_arg_default(raw_args, 'class', 'debug')
        assert exc_cls_name in self.exc_class_map
        exc_cls = self.exc_class_map[exc_cls_name]
        msg = get_arg_default(raw_args, 'msg', self.default_msg)
        threaded_reactor = asserted_cast(IReactorFromThreads, self._reactor)
        threaded_reactor.callFromThread(self.run, exc_cls, msg)
        return b'OK: no side-effects\n'


@register_resource
class DebugRejectResource(DebugRaiseResource):
    openapi = {
        '/_debug/reject': {
            'x-visibility': 'private',
            'get': {
                'operationId': 'debug_reject',
                'summary': 'Used for forcing an unhandled rejection on twisted. (has no side-effects)',
            }
        }
    }
    default_msg = 'deferred rejected for debugging purposes'

    def run(self, exc_cls: type[BaseException], msg: str) -> None:
        deferred: defer.Deferred[None] = defer.Deferred()
        deferred.errback(exc_cls(msg))


@register_resource
class DebugPrintResource(Resource):
    isLeaf = True
    openapi = {
        '/_debug/print': {
            'x-visibility': 'private',
            'get': {
                'operationId': 'debug_print',
                'summary': 'Used for forcing any print. (has no side-effects)',
            }
        }
    }
    default_msg = 'debugging python print'

    def render_GET(self, request: Request) -> bytes:
        raw_args = get_args(request)
        bargs = raw_args.get(b'msg')
        if bargs is not None:
            args = [a.decode() for a in bargs]
        else:
            args = [self.default_msg]
        if b'stderr' in raw_args:
            print(*args, file=sys.stderr)
        else:
            print(*args)
        return b'OK: no side-effects\n'


@register_resource
class DebugLogResource(Resource):
    isLeaf = True
    openapi = {
        '/_debug/log': {
            'x-visibility': 'private',
            'get': {
                'operationId': 'debug_log',
                'summary': 'Used for forcing any log message. (has no side-effects)',
            }
        }
    }
    valid_log_levels = {
        'critical',
        'debug',
        'error',
        'exception',
        'fatal',
        'info',
        'msg',
        'warn',
        'warning',
    }
    default_log_level = 'info'
    default_log_msg = 'debugging logging system'

    def render_GET(self, request: Request) -> bytes:
        raw_args = get_args(request)
        logger_name = get_arg_default(raw_args, 'logger', None)
        if logger_name is not None:
            log = get_logger(logger_name).new()
        else:
            log = logger.new()
        level = get_arg_default(raw_args, 'level', self.default_log_level)
        assert level in self.valid_log_levels
        log_func = getattr(log, level)
        msg = get_arg_default(raw_args, 'msg', self.default_log_msg)
        # TODO: maybe add an `extras` param (probably as a json body via POST) to add arbitrarily structed attributes
        log_func(msg)
        return b'OK: no side-effects\n'


@register_resource
class DebugMessAroundResource(Resource):
    isLeaf = True
    openapi = {
        '/_crash/mess_around': {
            'x-visibility': 'private',
            'get': {
                'operationId': 'debug_mess_around',
                'summary':
                    'Used for forcing an error on the full-node by messing with stuff, will probably leave database in'
                    'an inconsistent state. (NEVER ENABLE IN PRODUCTION)',
            }
        }
    }
    default_mess = 'storage'

    def __init__(self, manager: HathorManager):
        super().__init__()
        self.manager = manager
        # map is create here to be able to access the bound methods
        self.mess_map = {
            'storage': self.remove_storage,
        }

    def remove_storage(self) -> None:
        # XXX: this is just used to cause a problem on another part of the fullnode
        self.manager.tx_storage = None  # type: ignore

    def render_GET(self, request: Request) -> bytes:
        mess = get_arg_default(get_args(request), 'with', self.default_mess)
        assert mess in self.mess_map
        mess_func = self.mess_map[mess]
        threaded_reactor = asserted_cast(IReactorFromThreads, self.manager.reactor)
        threaded_reactor.callFromThread(mess_func)
        return b'OK: database yanked, full-node will break\n'


@register_resource
class DebugCrashResource(Resource):
    isLeaf = True
    openapi = {
        '/_crash/exit': {
            'x-visibility': 'private',
            'get': {
                'operationId': 'debug_crash',
                'summary':
                    'Used for forcing an unclean exit, this will almost certainly corrupt the database. '
                    '(NEVER ENABLE IN PRODUCTION)',
            }
        }
    }

    def __init__(self, reactor: ReactorProtocol) -> None:
        super().__init__()
        self._reactor = reactor

    def run(self, code: int) -> None:
        # XXX: sys.exit will raise a SystemExit exception that get's trapped by twisted
        #      os._exit will bypass that by exiting directly, note that no cleanup methods will be called
        os._exit(code)

    def render_GET(self, request: Request) -> bytes:
        code = get_arg_default(get_args(request), 'code', -1)
        self._reactor.callLater(1.0, self.run, code)
        return b'OK: full-node will exit and probably break database\n'
