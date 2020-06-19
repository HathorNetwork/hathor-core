"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import warnings
from collections import OrderedDict
from enum import Enum, Flag
from functools import partial, reduce, wraps
from operator import or_
from typing import Any, Callable, Deque, Dict, Iterable, Iterator, Tuple, Type, TypeVar, cast

from structlog import get_logger
from twisted.internet.interfaces import IReactorCore
from twisted.python.threadable import isInIOThread

from hathor.conf import HathorSettings

logger = get_logger()
settings = HathorSettings()


T = TypeVar('T')


def _get_tokens_issued_per_block(height: int) -> int:
    """Return the number of tokens issued per block of a given height.

    Always use Manager.get_tokens_issued_per_block.
    You should not use this method unless you know what you are doing.
    """
    if settings.BLOCKS_PER_HALVING is None:
        assert settings.MINIMUM_TOKENS_PER_BLOCK == settings.INITIAL_TOKENS_PER_BLOCK
        return settings.MINIMUM_TOKENS_PER_BLOCK

    number_of_halvings = (height - 1) // settings.BLOCKS_PER_HALVING
    number_of_halvings = max(0, number_of_halvings)

    if number_of_halvings > settings.MAXIMUM_NUMBER_OF_HALVINGS:
        return settings.MINIMUM_TOKENS_PER_BLOCK

    amount = settings.INITIAL_TOKENS_PER_BLOCK // (2**number_of_halvings)
    amount = max(amount, settings.MINIMUM_TOKENS_PER_BLOCK)
    return amount


def get_mined_tokens(height: int) -> int:
    """Return the number of tokens mined in total at height
    """
    assert settings.BLOCKS_PER_HALVING is not None
    number_of_halvings = (height - 1) // settings.BLOCKS_PER_HALVING
    number_of_halvings = max(0, number_of_halvings)

    blocks_in_this_halving = height - number_of_halvings * settings.BLOCKS_PER_HALVING

    tokens_per_block = settings.INITIAL_TOKENS_PER_BLOCK
    mined_tokens = 0

    # Sum the past halvings
    for _ in range(number_of_halvings):
        mined_tokens += settings.BLOCKS_PER_HALVING * tokens_per_block
        tokens_per_block //= 2
        tokens_per_block = max(tokens_per_block, settings.MINIMUM_TOKENS_PER_BLOCK)

    # Sum the blocks in the current halving
    mined_tokens += blocks_in_this_halving * tokens_per_block

    return mined_tokens


def practically_equal(a: Dict[Any, Any], b: Dict[Any, Any]) -> bool:
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


def deprecated(msg: str) -> Callable[..., Any]:
    """Use to indicate that a function or method has been deprecated."""
    warnings.simplefilter('default', DeprecationWarning)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # warnings.warn('{} is deprecated. {}'.format(func.__name__, msg),
            #               category=DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        wrapper.__deprecated = func  # type: ignore
        return wrapper

    return decorator


def skip_warning(func: Callable[..., Any]) -> Callable[..., Any]:
    f = cast(Callable[..., Any], getattr(func, '__deprecated', func))
    if hasattr(func, '__self__') and not hasattr(f, '__self__'):
        return partial(f, getattr(func, '__self__'))
    else:
        return f


class ReactorThread(Enum):
    MAIN_THREAD = 'MAIN_THREAD'
    NOT_MAIN_THREAD = 'NOT_MAIN_THREAD'
    NOT_RUNNING = 'NOT_RUNNING'

    @classmethod
    def get_current_thread(cls, reactor: IReactorCore) -> 'ReactorThread':
        """ Returns if the code is being run on the reactor thread, if it's running already.
        """
        if hasattr(reactor, 'running'):
            if reactor.running:
                return cls.MAIN_THREAD if isInIOThread() else cls.NOT_MAIN_THREAD
            else:
                # if reactor is not running yet, there's no threading
                return cls.NOT_RUNNING
        else:
            # on tests, we use Clock instead of a real Reactor, so there's
            # no threading. We consider that the reactor is running
            return cls.MAIN_THREAD


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
    from itertools import islice, takewhile, repeat
    idata = iter(array)
    return takewhile(bool, (bytes(islice(idata, chunk_size)) for _ in repeat(None)))


def iwindows(iterable: Iterable[T], window_size: int) -> Iterator[Tuple[T, ...]]:
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
    res_item: Deque[T] = deque()
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
    >>> foo
    MaxSizeOrderedDict([(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd'), (5, 'e')])
    >>> foo[6] = 'f'
    >>> foo
    MaxSizeOrderedDict([(2, 'b'), (3, 'c'), (4, 'd'), (5, 'e'), (6, 'f')])
    >>> foo[7] = 'g'
    >>> foo
    MaxSizeOrderedDict([(3, 'c'), (4, 'd'), (5, 'e'), (6, 'f'), (7, 'g')])
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


def json_loadb(raw: bytes) -> object:
    """Compact loading raw as UTF-8 encoded bytes to a Python object."""
    import json
    # XXX: from Python3.6 onwards, json.loads can take bytes
    #      See: https://docs.python.org/3/library/json.html#json.loads
    return json.loads(raw)


def json_dumpb(obj: object) -> bytes:
    """Compact formating obj as JSON to UTF-8 encoded bytes."""
    import json
    return json.dumps(obj, separators=(',', ':')).encode('utf-8')


def api_catch_exceptions(func: Callable[..., bytes]) -> Callable[..., bytes]:
    """Decorator to catch `hathor.exception.HathorError` and convert to API return type.

    Useful for annotating API methods and reduce error handling boilerplate.
    """
    from hathor.exception import HathorError
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except HathorError as e:
            return json_dumpb({'error': str(e)})
    return wrapper


# adapted from https://stackoverflow.com/a/42253518/947511
def enum_flag_all_none(enumeration: Type[Flag]) -> Type[Flag]:
    """Add NONE and ALL pseudo-members to enum.Flag classes"""
    none_mbr = enumeration(0)
    all_mbr = enumeration(reduce(or_, enumeration))
    enumeration._member_map_['NONE'] = none_mbr  # type: ignore
    enumeration._member_map_['ALL'] = all_mbr  # type: ignore
    return enumeration
