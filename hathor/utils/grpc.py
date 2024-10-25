#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
Utilities to handle gRPC server and client side code in a Twisted environment
Adapted from https://github.com/opencord/voltha/blob/master/common/utils/grpc_utils.py
"""

from concurrent.futures import Future
from typing import Callable, ParamSpec, TypeVar, cast

from structlog import get_logger
from twisted.internet.interfaces import IReactorFromThreads
from twisted.python.threadable import isInIOThread

from hathor.reactor import get_global_reactor

log = get_logger()

P = ParamSpec('P')
T = TypeVar('T')


def twisted_grpc(func: Callable[P, T]) -> Callable[P, T]:
    """
    This decorator can be used to implement a gRPC method on the twisted
    thread, allowing asynchronous programming in Twisted while serving
    a gRPC call.

    gRPC methods normally are called on the futures.ThreadPool threads,
    so these methods cannot directly use Twisted protocol constructs.
    If the implementation of the methods needs to touch Twisted, it is
    safer (or mandatory) to wrap the method with this decorator, which will
    call the inner method from the external thread and ensure that the
    result is passed back to the foreign thread.

    Example usage:

    When implementing a gRPC server, typical pattern is:

    class SpamService(SpamServicer):

        def GetBadSpam(self, request, context):
            '''this is called from a ThreadPoolExecutor thread'''
            # generally unsafe to make Twisted calls

        @twisted_grpc
        def GetSpamSafely(self, request, context):
            '''this method now is executed on the Twisted main thread
            # safe to call any Twisted protocol functions

        @twisted_grpc
        async def GetAsyncSpam(self, request, context):
            '''this generator can use inlineCallbacks Twisted style'''
            return await some_async_twisted_call(request)

    """
    reactor = cast(IReactorFromThreads, get_global_reactor())  # TODO: fix typing

    def in_thread_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        if isInIOThread():
            # This runs in Twisted's main thread
            return func(*args, **kwargs)

        # This runs in some gRPC thread
        future: Future[T] = Future()

        def twisted_wrapper() -> None:
            # This runs in Twisted's main thread
            try:
                result: T = func(*args, **kwargs)
                future.set_result(result)
                future.done()
            except Exception as e:
                future.set_exception(e)
                future.done()

        reactor.callFromThread(twisted_wrapper)
        try:
            result = future.result()
        except Exception:
            log.exception('unhandled exception in a gRPC method', func=func, args=args, kwargs=kwargs)
            raise

        return result

    return in_thread_wrapper
