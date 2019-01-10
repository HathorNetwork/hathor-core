import warnings
from functools import partial, wraps
from typing import Any, Callable


def deprecated(msg):
    """Use to indicate that a function or method has been deprecated."""
    warnings.simplefilter('default', DeprecationWarning)

    def decorator(func):
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            warnings.warn('{} is deprecated. {}'.format(func.__name__, msg), category=DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        wrapper.__deprecated = func
        return wrapper

    return decorator


def skip_warning(func: Callable) -> Callable:
    f = getattr(func, '__deprecated', func)
    if hasattr(func, '__self__') and not hasattr(f, '__self__'):
        return partial(f, getattr(func, '__self__'))
    else:
        return f
