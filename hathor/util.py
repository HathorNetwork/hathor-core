import warnings
from enum import Enum
from functools import partial, wraps
from typing import Any, Callable, Dict, Iterator, cast

from twisted.internet.defer import succeed
from twisted.internet.interfaces import IReactorCore
from twisted.python.threadable import isInIOThread
from twisted.web.iweb import IBodyProducer
from zope.interface import implementer


def practically_equal(a: Dict[Any, Any], b: Dict[Any, Any]):
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


@implementer(IBodyProducer)
class BytesProducer:
    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


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


class classproperty:
    """ This function is used to make a property that can be accessed from the class. Only getter is supported.

    See: https://stackoverflow.com/a/5192374/947511
    """

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)
