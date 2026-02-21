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

from __future__ import annotations

import datetime
import gc
import json
import math
import sys
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from functools import partial, wraps
from random import Random as PyRandom
from typing import TYPE_CHECKING, Any, Optional, TypeVar, cast

from structlog import get_logger

import hathor
from hathor.conf.get_settings import get_global_settings
from hathor.types import TokenUid, VertexId
from hathorlib.utils.json import json_dumpb  # noqa: F401

if TYPE_CHECKING:
    import structlog

    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.wallet import HDWallet

logger = get_logger()

T = TypeVar('T')


def practically_equal(a: dict[Any, Any], b: dict[Any, Any]) -> bool:
    """ Compare two defaultdict. It is used because a simple access have
    side effects in defaultdict.

    >>> from collections import defaultdict
    >>> a = defaultdict(list)
    >>> b = defaultdict(list)
    >>> a == b
    True
    >>> a[0]
    []
    >>> a == b
    False
    >>> practically_equal(a, b)
    True
    """
    for k, v in a.items():
        if v != b[k]:
            return False
    for k, v in b.items():
        if v != a[k]:
            return False
    return True


def skip_warning(func: Callable[..., Any]) -> Callable[..., Any]:
    f = cast(Callable[..., Any], getattr(func, '__deprecated', func))
    if hasattr(func, '__self__') and not hasattr(f, '__self__'):
        return partial(f, getattr(func, '__self__'))
    else:
        return f


def abbrev(data: bytes, max_len: int = 256, gap: bytes = b' [...] ') -> bytes:
    """ Abbreviates data, mostly for less verbose but still useful logging.

    Examples:

    >>> abbrev(b'foobar barbaz', 9, b'...')
    b'foo...baz'

    >>> abbrev(b'foobar barbaz', 9, b'..')
    b'foob..baz'

    >>> abbrev(b'foobar barbaz', 9, b'.')
    b'foob.rbaz'
    """
    if len(data) <= max_len:
        return data
    trim_len = max_len - len(gap)
    assert trim_len > 1, 'max_len and gap should be such that it leaves room for 1 byte on each side'
    tail_len = trim_len // 2
    head_len = trim_len - tail_len
    return data[:head_len] + gap + data[-tail_len:]


def ichunks(array: bytes, chunk_size: int) -> Iterator[bytes]:
    """ Split and yield chunks of the given size.
    """
    from itertools import islice, repeat, takewhile
    idata = iter(array)
    return takewhile(bool, (bytes(islice(idata, chunk_size)) for _ in repeat(None)))


def iwindows(iterable: Iterable[T], window_size: int) -> Iterator[tuple[T, ...]]:
    """ Adapt iterator to yield windows of the given size.

    window_size must be greater than 0

    Example:

    >>> list(iwindows([1, 2, 3, 4], 2))
    [(1, 2), (2, 3), (3, 4)]

    >>> list(iwindows([1, 2, 3, 4], 3))
    [(1, 2, 3), (2, 3, 4)]

    >>> list(iwindows([1, 2, 3, 4], 1))
    [(1,), (2,), (3,), (4,)]
    """
    from collections import deque
    it = iter(iterable)
    assert window_size > 0
    res_item: deque[T] = deque()
    while len(res_item) < window_size:
        res_item.append(next(it))
    yield tuple(res_item)
    for item in it:
        res_item.popleft()
        res_item.append(item)
        yield tuple(res_item)


class classproperty:
    """ This function is used to make a property that can be accessed from the class. Only getter is supported.

    See: https://stackoverflow.com/a/5192374/947511
    """

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)


class MaxSizeOrderedDict(OrderedDict):
    """ And OrderedDict that has a maximum size, if new elements are added, the oldest elements are silently deleted.

    Examples:

    >>> foo = MaxSizeOrderedDict(max=5)
    >>> foo[1] = 'a'
    >>> foo[2] = 'b'
    >>> foo[3] = 'c'
    >>> foo[4] = 'd'
    >>> foo[5] = 'e'
    >>> list(foo.items())
    [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd'), (5, 'e')]
    >>> foo[6] = 'f'
    >>> list(foo.items())
    [(2, 'b'), (3, 'c'), (4, 'd'), (5, 'e'), (6, 'f')]
    >>> foo[7] = 'g'
    >>> list(foo.items())
    [(3, 'c'), (4, 'd'), (5, 'e'), (6, 'f'), (7, 'g')]
    """
    # Kindly stolen from: https://stackoverflow.com/a/49274421/947511
    def __init__(self, *args, max=0, **kwargs):
        self._max = max
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        if self._max > 0:
            if len(self) > self._max:
                self.popitem(False)


def json_loadb(raw: bytes) -> dict:
    """Compact loading as UTF-8 encoded bytes/string to a Python object."""
    import json

    # XXX: from Python3.6 onwards, json.loads can take bytes
    #      See: https://docs.python.org/3/library/json.html#json.loads
    try:
        return json.loads(raw)
    except UnicodeDecodeError as exc:
        # We cannot do `doc=raw` because it expects a str and there
        # is no way to decode it.
        raise json.JSONDecodeError(msg=str(exc), doc=raw.hex(), pos=exc.start) from exc


# XXX: cast-converting the function saves a function-call, which can make a difference
json_loads = cast(Callable[[str], dict], json_loadb)


def json_dumps(obj: object) -> str:
    """Compact formating obj as JSON to UTF-8 encoded string."""
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)


def api_catch_exceptions(func: Callable[..., bytes]) -> Callable[..., bytes]:
    """Decorator to catch `hathor.exception.HathorError` and convert to API return type.

    Useful for annotating API methods and reduce error handling boilerplate.
    """
    from autobahn.twisted.websocket import WebSocketAdapterProtocol
    from twisted.web.http import Request
    from twisted.web.resource import Resource

    from hathor.exception import HathorError

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except HathorError as e:
            self = args[0] if len(args) > 0 else None
            if isinstance(self, Resource):
                request = cast(Optional[Request], args[1] if len(args) > 1 else None)
                if request is not None:
                    request.setResponseCode(getattr(e, 'status_code', 500))
                return json_dumpb({'error': str(e)})
            elif isinstance(self, WebSocketAdapterProtocol):
                self.sendClose(reason=json_dumpb({'error': str(e)}))
            else:
                logger.error('could not handle error', args=args, error=e)
                raise  # reraise because we don't know how to handle this
    return wrapper


class LogDuration(float):
    def __str__(x):
        if x >= 1:
            return f'~{math.trunc(x)}s'
        elif x >= 0.001:
            return f'~{math.trunc(x * 1000)}ms'
        else:
            return '<1ms'
    __repr__ = __str__


# borrowed from: https://github.com/facebook/pyre-check/blob/master/pyre_extensions/__init__.py
def not_none(optional: Optional[T], message: str = 'Unexpected `None`') -> T:
    """Convert an optional to its value. Raises an `AssertionError` if the
    value is `None`"""
    if optional is None:
        raise AssertionError(message)
    return optional


class Random(PyRandom):
    def geometric(self, p: float) -> int:
        """Port of numpy.random.Generator.geometric sampling

        It uses the Inverse Transform Sampling [1].
        CDF(x) = 1 - (1 - p)**x
        CDF^{-1}(x) = log(1 - x) / log(1 - p)
        [1] https://en.wikipedia.org/wiki/Inverse_transform_sampling
        """
        return math.ceil(math.log(self.random()) / math.log(1 - p))

    def ordered_sample(self, seq: Sequence[T], k: int) -> list[T]:
        """Like self.sample but preserve orginal order.

        For example, ordered_sample([1, 2, 3]) will never return [3, 2] only [2, 3] instead."""
        return [x for _, x in sorted(self.sample(list(enumerate(seq)), k))]

    # XXX: backport of randbytes from https://github.com/python/cpython/blob/3.9/Lib/random.py#L283-L285
    if not hasattr(PyRandom, 'randbytes'):
        def randbytes(self, n):
            """Generate n random bytes."""
            return self.getrandbits(n * 8).to_bytes(n, 'little')


def collect_n(it: Iterator[T], n: int) -> tuple[list[T], bool]:
    """Collect up to n elements from an iterator into a list, returns the list and whether there were more elements.

    This method will consume up to n+1 elements from the iterator because it will try to get one more element after it
    has n elements to check if there are more.

    Example:

    >>> collect_n(iter(range(10)), 10)
    ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], False)

    >>> collect_n(iter(range(10)), 11)
    ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], False)

    >>> collect_n(iter(range(10)), 9)
    ([0, 1, 2, 3, 4, 5, 6, 7, 8], True)

    >>> collect_n(iter(range(10)), 8)
    ([0, 1, 2, 3, 4, 5, 6, 7], True)

    # This also works for checking (albeit destructively, because it consumes from the itreator), if it is empty

    >>> collect_n(iter(range(10)), 0)
    ([], True)
    """
    if n < 0:
        raise ValueError(f'n must be non-negative, got {n}')
    col: list[T] = []
    has_more = False
    while n > 0:
        try:
            elem = next(it)
            has_more = True
        except StopIteration:
            has_more = False
            break
        n -= 1
        col.append(elem)
    else:
        try:
            next(it)
            has_more = True
        except StopIteration:
            has_more = False
    return col, has_more


def skip_n(it: Iterator[T], n: int) -> Iterator[T]:
    """ Skip at least n elements if possible.

    Example:

    >>> list(skip_n(iter(range(10)), 0))
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    >>> list(skip_n(iter(range(10)), 1))
    [1, 2, 3, 4, 5, 6, 7, 8, 9]

    >>> list(skip_n(iter(range(10)), 9))
    [9]

    >>> list(skip_n(iter(range(10)), 10))
    []

    >>> list(skip_n(iter(range(10)), 11))
    []
    """
    for _ in range(n):
        try:
            next(it)
        except StopIteration:
            return it
    return it


def skip_until(it: Iterator[T], condition: Callable[[T], bool]) -> Iterator[T]:
    """ Skip all elements and stops after condition is True, it will also skip the element where condition is True.

    Example:

    >>> list(skip_until(iter(range(10)), lambda x: x == 0))
    [1, 2, 3, 4, 5, 6, 7, 8, 9]

    >>> list(skip_until(iter(range(10)), lambda x: x > 0))
    [2, 3, 4, 5, 6, 7, 8, 9]

    >>> list(skip_until(iter(range(10)), lambda x: x == 8))
    [9]

    >>> list(skip_until(iter(range(10)), lambda x: x == 9))
    []

    >>> list(skip_until(iter(range(10)), lambda x: x == 10))
    []
    """
    while True:
        try:
            i = next(it)
        except StopIteration:
            return it
        else:
            if condition(i):
                break
    return it


_DT_ITER_NEXT_WARN = 3  # time in seconds to warn when `next(iter_tx)` takes too long
_DT_LOG_PROGRESS = 10  # time in seconds after which a progress will be logged (it can take longer, but not shorter)
_DT_YIELD_WARN = 1  # time in seconds to warn when `yield tx` takes too long (which is when processing happens)


def progress(
    it: Iterator[T],
    *,
    log: 'structlog.stdlib.BoundLogger',
    total: Optional[int]
) -> Iterator[T]:
    """ Implementation of progress helper for using with an iterator of any type.

    This is basically a stripped down version of `hathor.util.progress`
    """
    t_start = time.time()
    count = 0
    count_log_prev = 0
    if total:
        log.info('loading... 0%', progress=0)
    else:
        log.info('loading...')
    t_log_prev = t_start
    while True:
        try:
            item = next(it)
        except StopIteration:
            break

        t_log = time.time()
        dt_log = LogDuration(t_log - t_log_prev)
        if dt_log > _DT_LOG_PROGRESS:
            t_log_prev = t_log
            dcount = count - count_log_prev
            rate = '?' if dt_log == 0 else dcount / dt_log
            kwargs = dict(rate=rate, new=dcount, dt=dt_log, total=count)
            if total:
                progress_ = count / total
                elapsed_time = t_log - t_start
                remaining_time = LogDuration(elapsed_time / progress_ - elapsed_time)
                log.info(
                    f'loading... {math.floor(progress_ * 100):2.0f}%',
                    progress=progress_,
                    remaining_time=remaining_time,
                    **kwargs
                )
            else:
                log.info('loading...', **kwargs)
            count_log_prev = count
        count += 1

        yield item

    t_final = time.time()
    dt_total = LogDuration(t_final - t_start)
    rate = '?' if dt_total == 0 else count / dt_total
    if total:
        progress_ = count / total
        log.info(f'loaded...  {math.floor(progress_ * 100):2.0f}%', progress=progress_, count=count, rate=rate,
                 total_dt=dt_total)
    else:
        log.info('loaded', count=count, rate=rate, total_dt=dt_total)


def tx_progress(
    iter_tx: Iterator['BaseTransaction'],
    *,
    log: Optional['structlog.stdlib.BoundLogger'] = None,
    total: Optional[int] = None,
    show_height_and_ts: bool = False,
) -> Iterator['BaseTransaction']:
    """ Log the progress of a transaction iterator while iterating.
    """
    if log is None:
        log = logger.new()

    yield from _tx_progress(iter_tx, log=log, total=total, show_height_and_ts=show_height_and_ts)


def _tx_progress(
    iter_tx: Iterator['BaseTransaction'],
    *,
    log: 'structlog.stdlib.BoundLogger',
    total: Optional[int],
    show_height_and_ts: bool,
) -> Iterator['BaseTransaction']:
    """ Inner implementation of progress helper.
    """
    t_start = time.time()
    h = 0
    ts_tx = 0

    count = 0
    count_log_prev = 0
    block_count = 0
    tx_count = 0
    first_log = True

    log.debug('load will start')
    t_log_prev = t_start
    while True:
        t_before_next = time.time()
        try:
            tx: 'BaseTransaction' = next(iter_tx)
        except StopIteration:
            break
        t_after_next = time.time()
        dt_next = LogDuration(t_after_next - t_before_next)
        if dt_next > _DT_ITER_NEXT_WARN:
            log.warn('iterator was slow to yield', took_sec=dt_next)

        # XXX: this is only informative and made to work with either partially/fully validated blocks/transactions
        from hathor.transaction import Block
        if isinstance(tx, Block):
            h = max(h, tx.static_metadata.height)
        ts_tx = max(ts_tx, tx.timestamp)

        t_log = time.time()
        dt_log = LogDuration(t_log - t_log_prev)
        if first_log or dt_log > _DT_LOG_PROGRESS:
            first_log = False
            t_log_prev = t_log
            dcount = count - count_log_prev
            tx_rate = '?' if dt_log == 0 else dcount / dt_log
            ts = datetime.datetime.fromtimestamp(ts_tx)
            kwargs: dict[str, Any] = dict(tx_rate=tx_rate, tx_new=dcount, dt=dt_log, total=count)
            if show_height_and_ts:
                kwargs.update(latest_ts=ts, height=h)
            if total:
                progress_ = count / total
                elapsed_time = t_log - t_start
                remaining_time: str | LogDuration
                if progress_ == 0:
                    remaining_time = '?'
                else:
                    remaining_time = LogDuration(elapsed_time / progress_ - elapsed_time)
                log.info(
                    f'loading... {math.floor(progress_ * 100):2.0f}%',
                    remaining_time=remaining_time,
                    **kwargs
                )
            else:
                log.info('loading...', **kwargs)
            count_log_prev = count
        count += 1

        t_before_yield = time.time()
        yield tx
        t_after_yield = time.time()

        if tx.is_block:
            block_count += 1
        else:
            tx_count += 1

        dt_yield = t_after_yield - t_before_yield
        if dt_yield > _DT_YIELD_WARN:
            dt = LogDuration(dt_yield)
            # The loglevel was changed to debug because most of the causes of slowness
            # is related to the gc acting during the tx processing. We had previously
            # disabled the gc but it caused a too high CPU usage.
            log.debug('tx took too long to be processed (gc?!)', tx=tx.hash_hex, dt=dt)

    t_final = time.time()
    dt_total = LogDuration(t_final - t_start)
    tx_rate = '?' if dt_total == 0 else count / dt_total
    kwargs = dict(tx_count=count, tx_rate=tx_rate, total_dt=dt_total, blocks=block_count, txs=tx_count)
    if show_height_and_ts:
        kwargs.update(height=h)
    log.info('loaded', **kwargs)


class peekable(Iterator[T]):
    """Adaptor class to peek what will be returned by next(iterator)


    >>> it = peekable(range(10))
    >>> iter(it) is it
    True
    >>> it.peek()
    0
    >>> next(it)
    0
    >>> next(it)
    1
    >>> it.peek()
    2
    >>> bool(it)
    True
    >>> next(it)
    2
    >>> list(it)
    [3, 4, 5, 6, 7, 8, 9]
    >>> bool(it)
    False
    >>> it.peek()
    Traceback (most recent call last):
    ...
    ValueError: iterator was exhausted

    """

    def __init__(self, it: Iterable[T]) -> None:
        self._it: Optional[Iterator[T]] = iter(it)
        # XXX: using Optional[tuple[T]] makes it so the iterator can yield None, and it would be correctly peekable,
        #      which is different from not having a next element to peek into
        self._head: Optional[tuple[T]] = None

    def _peek(self) -> Optional[tuple[T]]:
        if self._head is None and self._it is None:
            return None
        if self._head is None:
            assert self._it is not None
            try:
                self._head = next(self._it),
            except StopIteration:
                self._it = None
                return None
        return self._head

    def __iter__(self) -> Iterator[T]:
        return self

    def __next__(self) -> T:
        if self._head is not None:
            (x,), self._head = self._head, None
            return x
        elif self._it is not None:
            try:
                return next(self._it)
            except StopIteration:
                self.it = None
                raise
        else:
            raise StopIteration()

    def peek(self) -> T:
        x = self._peek()
        if x is None:
            raise ValueError('iterator was exhausted')
        y, = x
        return y

    def __bool__(self) -> bool:
        return self._peek() is not None


def _identity(x: T) -> T:
    return x


class sorted_merger(Iterator[T]):
    """ Adaptor class to merge multiple sorted iterators into a single iterator that is also sorted.

    Note: for this adaptor to work as expected the input iterators have to already be sorted, but if they aren't, the
    resulting iterator won't crash, or unexpectedly stop working, however it will not be sorted.

    A custom key function can be supplied to customize the sort order, and the
    reverse flag can be set to request the result in descending order.

    The implemented logic is really simple:

    - Peek the next element in each iterator, and yield from the "smallest" one (according to the key function and the
      reversed flag), when an iterator is exhausted it's just removed from the list until the list is empty, in which
      point the resulting iterator will stop.

    For example:

    >>> list(sorted_merger([1,3,4,100,101,105], [104], [2,50,99,106]))
    [1, 2, 3, 4, 50, 99, 100, 101, 104, 105, 106]

    For descending order, use reverse=True

    >>> list(sorted_merger([105,101,100,4,3,1], [104], [106,99,50,2], reverse=True))
    [106, 105, 104, 101, 100, 99, 50, 4, 3, 2, 1]

    But using a negating key also works

    >>> list(sorted_merger([105,101,100,4,3,1], [104], [106,99,50,2], key=lambda i: -i))
    [106, 105, 104, 101, 100, 99, 50, 4, 3, 2, 1]

    Empty stuff will just yield empty stuff

    >>> list(sorted_merger([]))
    []

    >>> list(sorted_merger())
    []

    All elements will eventually be yielded, it doesn't matter if they are "repeated"

    >>> list(sorted_merger([], [1,1,1], [1,1], [1,1,1,1]))
    [1, 1, 1, 1, 1, 1, 1, 1, 1]

    Even if they are not sorted, they will still be yielded eventually, but there are no guarantees about the order
    they will come out

    >>> list(sorted_merger([1,2,3],[4,3,2]))
    [1, 2, 3, 4, 3, 2]
    """

    def __init__(self, *iterators: Iterator[T], key: Optional[Callable[[T], Any]] = None,
                 reverse: bool = False) -> None:
        self._iterators = [peekable(it) for it in iterators]
        self._key = key or _identity
        self._reverse = reverse

    def _clear_empty(self):
        for it in self._iterators[:]:
            if not it:
                self._iterators.remove(it)

    def __iter__(self) -> Iterator[T]:
        return self

    def __next__(self) -> T:
        self._clear_empty()
        if not self._iterators:
            raise StopIteration
        cmp = max if self._reverse else min
        # XXX: this line below is correct, but it's just really hard to convince mypy of that, ignoring for now
        best_it = cmp(self._iterators, key=lambda it: self._key(it.peek()))  # type: ignore
        return next(best_it)


class manualgc(AbstractContextManager):
    """This context is useful for making a region where the garbage collection will be disabled (not automatic).

    The main advantage for using a context is not having to worry about how exceptions will affect the state
    consistency. The gc will be correctly re-enabled after exiting regardless if the context was exited because of an
    exception.

    >>> gc.isenabled()
    True
    >>> with manualgc():
    ...     gc.isenabled()
    False
    >>> gc.isenabled()
    True

    Nesting should work as expected:

    >>> with manualgc():
    ...     with manualgc():
    ...         gc.isenabled()
    ...     gc.isenabled()
    False
    False
    >>> gc.isenabled()
    True

    As well as exiting from an exception:

    >>> with manualgc():
    ...     raise RuntimeError('foo')
    Traceback (most recent call last):
    ...
    RuntimeError: foo
    >>> gc.isenabled()
    True

    Even if exception is nested:

    >>> with manualgc():
    ...     with manualgc():
    ...         raise RuntimeError('bar')
    Traceback (most recent call last):
    ...
    RuntimeError: bar
    >>> gc.isenabled()
    True

    """

    _nest_count: int = 0

    def __enter__(self):
        if type(self)._nest_count == 0:
            gc.disable()
        type(self)._nest_count += 1

    def __exit__(self, exc_type, exc_val, exc_tb):
        type(self)._nest_count -= 1
        if type(self)._nest_count == 0:
            gc.enable()


def is_token_uid_valid(token_uid: TokenUid) -> bool:
    """ Checks whether a byte sequence can be a valid token UID.

    >>> is_token_uid_valid(bytes.fromhex('00'))
    True

    >>> is_token_uid_valid(bytes.fromhex('1234'))
    False

    >>> is_token_uid_valid(bytes.fromhex('000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb824'))
    True

    >>> is_token_uid_valid(bytes.fromhex('000003a3b261e142d3dfd84970d3a50a93b5bc3a66a3b6ba973956148a3eb82400'))
    False
    """
    settings = get_global_settings()
    if token_uid == settings.HATHOR_TOKEN_UID:
        return True
    elif len(token_uid) == 32:
        return True
    else:
        return False


@dataclass
class EnvironmentInfo:
    # Changing these names could impact logging collectors that parse them
    python_implementation: str
    hathor_core_args: str
    hathor_core_version: str
    peer_id: Optional[str]
    network: str
    network_full: str

    def as_dict(self):
        return asdict(self)


def get_environment_info(args: str, peer_id: Optional[str]) -> EnvironmentInfo:
    settings = get_global_settings()
    environment_info = EnvironmentInfo(
        python_implementation=str(sys.implementation),
        hathor_core_args=args,
        hathor_core_version=get_hathor_core_version(),
        peer_id=peer_id,
        network_full=settings.NETWORK_NAME,
        # We want to ignore the testnet suffixes here. "testnet-india" should be reported only as "testnet".
        network=settings.NETWORK_NAME.split("-")[0]
    )

    return environment_info


def get_hathor_core_version():
    return hathor.__version__


def bytes_to_vertexid(data: bytes) -> VertexId:
    # XXX: using raw string for the docstring so we can more easily write byte literals
    r""" Function to validate bytes and return a VertexId, raises ValueError if not valid.

    >>> bytes_to_vertexid(b'\0' * 32)
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    >>> bytes_to_vertexid(b'\0' * 31)
    Traceback (most recent call last):
    ...
    ValueError: length must be exactly 32 bytes
    >>> bytes_to_vertexid(b'\0' * 33)
    Traceback (most recent call last):
    ...
    ValueError: length must be exactly 32 bytes
    """
    if len(data) != 32:
        raise ValueError('length must be exactly 32 bytes')
    return VertexId(data)


def bytes_from_hex(hex_str: str) -> bytes | None:
    """Convert a hex string to bytes or return None if it's invalid."""
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def initialize_hd_wallet(words: str) -> HDWallet:
    """Get an initialized HDWallet from the provided words."""
    from hathor.wallet import HDWallet
    hd = HDWallet(words=words)
    hd._manually_initialize()
    return hd
