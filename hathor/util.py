import warnings
from enum import Enum
from functools import partial, wraps
from typing import Any, Callable, Dict, cast

from twisted.internet.interfaces import IReactorCore
from twisted.python.threadable import isInIOThread


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
