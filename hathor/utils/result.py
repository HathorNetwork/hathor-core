#  Copyright 2025 Hathor Labs
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

from __future__ import annotations

import functools
import inspect
import traceback
from collections import deque
from typing import Any, Awaitable, Callable, Final, Generic, Literal, NoReturn, ParamSpec, Type, TypeAlias, TypeVar

from typing_extensions import TypeIs

T = TypeVar('T', covariant=True)  # Success type
E = TypeVar('E', covariant=True)  # Error type
U = TypeVar('U')
F = TypeVar('F')
P = ParamSpec('P')
TE = TypeVar('TE', bound=Exception)


class Ok(Generic[T]):
    """
    A value that indicates success and which stores arbitrary data for the return value.
    """

    __slots__ = ('_value',)
    __match_args__ = ('_value',)

    def __init__(self, value: T) -> None:
        self._value = value

    def __repr__(self) -> str:
        return f'Ok({self._value!r})'

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Ok) and self._value == other._value

    def __ne__(self, other: Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((True, self._value))

    def is_ok(self) -> Literal[True]:
        return True

    def is_err(self) -> Literal[False]:
        return False

    def ok(self) -> T:
        """
        Return the value.
        """
        return self._value

    def err(self) -> None:
        """
        Return `None`.
        """
        return None

    def expect(self, _message: str) -> T:
        """
        Return the value.
        """
        return self._value

    def expect_err(self, message: str) -> NoReturn:
        """
        Raise an UnwrapError since this type is `Ok`
        """
        raise UnwrapError(self, message)

    def unwrap(self) -> T:
        """
        Return the value.
        """
        return self._value

    def unwrap_err(self) -> NoReturn:
        """
        Raise an UnwrapError since this type is `Ok`
        """
        raise UnwrapError(self, 'Called `Result.unwrap_err()` on an `Ok` value')

    def unwrap_or(self, _default: U) -> T:
        """
        Return the value.
        """
        return self._value

    def unwrap_or_else(self, _op: Callable[[E], T]) -> T:
        """
        Return the value.
        """
        return self._value

    def unwrap_or_raise(self) -> T:
        """
        Return the value.
        """
        return self._value

    def unwrap_or_raise_another(self, _e: Type[TE]) -> T:
        """
        Return the value.
        """
        return self._value

    def unwrap_or_propagate(self) -> T:
        """
        Return the value.
        """
        return self._value

    def map(self, op: Callable[[T], U]) -> Ok[U]:
        """
        The contained result is `Ok`, so return `Ok` with original value mapped to
        a new value using the passed in function.
        """
        return Ok(op(self._value))

    async def map_async(self, op: Callable[[T], Awaitable[U]]) -> Ok[U]:
        """
        The contained result is `Ok`, so return the result of `op` with the
        original value passed in
        """
        return Ok(await op(self._value))

    def map_or(self, _default: U, op: Callable[[T], U]) -> U:
        """
        The contained result is `Ok`, so return the original value mapped to a new
        value using the passed in function.
        """
        return op(self._value)

    def map_or_else(self, default_op: Callable[[], U], op: Callable[[T], U]) -> U:
        """
        The contained result is `Ok`, so return original value mapped to
        a new value using the passed in `op` function.
        """
        return op(self._value)

    def map_err(self, _op: Callable[[E], F]) -> Ok[T]:
        """
        The contained result is `Ok`, so return `Ok` with the original value
        """
        return self

    def and_then(self, op: Callable[[T], Result[U, E]]) -> Result[U, E]:
        """
        The contained result is `Ok`, so return the result of `op` with the
        original value passed in
        """
        return op(self._value)

    async def and_then_async(self, op: Callable[[T], Awaitable[Result[U, E]]]) -> Result[U, E]:
        """
        The contained result is `Ok`, so return the result of `op` with the
        original value passed in
        """
        return await op(self._value)

    def or_else(self, _op: Callable[[E], Result[T, F]]) -> Ok[T]:
        """
        The contained result is `Ok`, so return `Ok` with the original value
        """
        return self

    def inspect(self, op: Callable[[T], Any]) -> Result[T, E]:
        """
        Calls a function with the contained value if `Ok`. Returns the original result.
        """
        op(self._value)
        return self

    def inspect_err(self, op: Callable[[E], Any]) -> Result[T, E]:
        """
        Calls a function with the contained value if `Err`. Returns the original result.
        """
        return self


class Err(Generic[E]):
    """
    A value that signifies failure and which stores arbitrary data for the error.
    """

    __slots__ = ('_value', 'traceback')
    __match_args__ = ('_value',)

    def __init__(self, value: E, cause: Exception | None = None) -> None:
        self._value = value
        self.traceback: str | None

        if cause is not None:
            # when a cause is provided, we use it.
            assert cause.__traceback__ is not None, 'cause must only be used from a try-except context'
            self.traceback = traceback.format_exc()
            return

        if not isinstance(value, Exception):
            # when value is not an Exception, we don't try to extract a traceback.
            self.traceback = None
            return

        if value.__traceback__ is not None:
            # when value is an exception with a traceback, we can format it.
            self.traceback = traceback.format_exc()
            return

        # when value is an exception without a traceback, we have to capture it ourselves.
        self.traceback = self._capture_traceback(value)

    @staticmethod
    def _capture_traceback(e: Exception) -> str:
        """
        Capture the current call stack as a traceback string, formatted like a real exception.
        Uses traceback.extract_stack() which is more portable than sys._getframe().
        """
        from hathor import HATHOR_DIR
        from tests import TESTS_DIR  # skip-import-tests-custom-check

        # Use traceback.extract_stack to get the current stack
        # This is more portable than sys._getframe()
        stack = list(traceback.extract_stack())

        # Remove the last 2 frames (Err.__init__ and Err._capture_traceback)
        stack = stack[:-2]

        # Filter stack to start from the first frame in /hathor or /tests
        filtered_stack: deque[traceback.FrameSummary] = deque()

        # Consume iterator until we find the first relevant frame
        for frame in reversed(stack):
            if not frame.filename.startswith(HATHOR_DIR) and not frame.filename.startswith(TESTS_DIR):
                break
            filtered_stack.appendleft(frame)

        # Build the traceback string
        tb_lines = ['Traceback (most recent call last):\n']
        tb_lines.extend(traceback.format_list(filtered_stack))

        # Add the exception info
        tb_lines.append(f'{type(e).__module__}:{type(e).__qualname__}: {e}\n')

        return ''.join(tb_lines)

    def __repr__(self) -> str:
        return f'Err({self._value!r})'

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Err) and self._value == other._value

    def __ne__(self, other: Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((False, self._value))

    def is_ok(self) -> Literal[False]:
        return False

    def is_err(self) -> Literal[True]:
        return True

    def ok(self) -> None:
        """
        Return `None`.
        """
        return None

    def err(self) -> E:
        """
        Return the error.
        """
        return self._value

    def expect(self, message: str) -> NoReturn:
        """
        Raises an `UnwrapError`.
        """
        exc = UnwrapError(
            self,
            f'{message}: {self._value!r}',
        )
        if isinstance(self._value, BaseException):
            raise exc from self._value
        raise exc

    def expect_err(self, _message: str) -> E:
        """
        Return the inner value
        """
        return self._value

    def unwrap(self) -> NoReturn:
        """
        Raises an `UnwrapError`.
        """
        exc = UnwrapError(
            self,
            f'Called `Result.unwrap()` on an `Err` value: {self._value!r}',
        )
        if isinstance(self._value, BaseException):
            raise exc from self._value
        raise exc

    def unwrap_err(self) -> E:
        """
        Return the inner value
        """
        return self._value

    def unwrap_or(self, default: U) -> U:
        """
        Return `default`.
        """
        return default

    def unwrap_or_else(self, op: Callable[[E], T]) -> T:
        """
        The contained result is `Err`, so return the result of applying
        `op` to the error value.
        """
        return op(self._value)

    def unwrap_or_raise(self) -> NoReturn:
        """
        The contained result is `Err`, so raise the exception with the value.
        """
        assert isinstance(self._value, Exception), (
            f'called `Result.unwrap_or_raise()` on non-exception value: {self._value}'
        )
        raise self._value

    def unwrap_or_raise_another(self, e: Type[TE]) -> NoReturn:
        """
        The contained result is `Err`, so raise the exception with the value.
        """
        raise e(self._value)

    def unwrap_or_propagate(self) -> NoReturn:
        """
        The contained result is ``Err``, raise DoException with self.
        """
        raise _ResultPropagationException(self)

    def map(self, _op: Callable[[T], U]) -> Err[E]:
        """
        Return `Err` with the same value
        """
        return self

    async def map_async(self, _op: Callable[[T], Awaitable[U]]) -> Err[E]:
        """
        The contained result is `Ok`, so return the result of `op` with the
        original value passed in
        """
        return self

    def map_or(self, default: U, _op: Callable[[T], U]) -> U:
        """
        Return the default value
        """
        return default

    def map_or_else(self, default_op: Callable[[], U], _op: Callable[[T], U]) -> U:
        """
        Return the result of the default operation
        """
        return default_op()

    def map_err(self, op: Callable[[E], F]) -> Err[F]:
        """
        The contained result is `Err`, so return `Err` with original error mapped to
        a new value using the passed in function.
        """
        return Err(op(self._value))

    def and_then(self, _op: Callable[[T], Result[U, E]]) -> Err[E]:
        """
        The contained result is `Err`, so return `Err` with the original value
        """
        return self

    async def and_then_async(self, _op: Callable[[T], Awaitable[Result[U, E]]]) -> Err[E]:
        """
        The contained result is `Err`, so return `Err` with the original value
        """
        return self

    def or_else(self, op: Callable[[E], Result[T, F]]) -> Result[T, F]:
        """
        The contained result is `Err`, so return the result of `op` with the
        original value passed in
        """
        return op(self._value)

    def inspect(self, op: Callable[[T], Any]) -> Result[T, E]:
        """
        Calls a function with the contained value if `Ok`. Returns the original result.
        """
        return self

    def inspect_err(self, op: Callable[[E], Any]) -> Result[T, E]:
        """
        Calls a function with the contained value if `Err`. Returns the original result.
        """
        op(self._value)
        return self


"""
A simple `Result` type inspired by Rust.
Not all methods (https://doc.rust-lang.org/std/result/enum.Result.html)
have been implemented, only the ones that make sense in the Python context.
"""
Result: TypeAlias = Ok[T] | Err[E]

"""
A type to use in `isinstance` checks.
This is purely for convenience's sake, as you could also just write `isinstance(res, (Ok, Err))`
"""
OkErr: Final = (Ok, Err)


class UnwrapError(Exception):
    """
    Exception raised from `.unwrap_*` and `.expect_*` calls.

    The original `Result` can be accessed via the `.result` attribute, but
    this is not intended for regular use, as type information is lost:
    `UnwrapError` doesn't know about both `T` and `E`, since it's raised
    from `Ok()` or `Err()` which only knows about either `T` or `E`,
    not both.
    """

    _result: Result[Any, Any]

    def __init__(self, result: Result[Any, Any], message: str) -> None:
        super().__init__(message)
        self._result = result

    @property
    def result(self) -> Result[Any, Any]:
        """
        Returns the original result.
        """
        return self._result


class _ResultPropagationException(Exception):
    def __init__(self, err: Err[E]) -> None:
        super().__init__('did you forget to annotate the function/method with `@propagate_result`?')
        self.err = err


def propagate_result(f: Callable[P, Result[T, E]]) -> Callable[P, Result[T, E]]:
    """
    Decorator to turn a function into one that allows using unwrap_or_return.
    """
    @functools.wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T, E]:
        try:
            return f(*args, **kwargs)
        except _ResultPropagationException as e:
            return e.err  # type: ignore[return-value]

    return wrapper


def as_result(
    *exceptions: Type[TE],
) -> Callable[[Callable[P, T]], Callable[P, Result[T, TE]]]:
    """
    Make a decorator to turn a function into one that returns a `Result`.

    Regular return values are turned into `Ok(return_value)`. Raised
    exceptions of the specified exception type(s) are turned into `Err(exc)`.
    """
    if not exceptions or not all(
        inspect.isclass(exception) and issubclass(exception, BaseException)
        for exception in exceptions
    ):
        raise TypeError('as_result() requires one or more exception types')

    def decorator(f: Callable[P, T]) -> Callable[P, Result[T, TE]]:
        """
        Decorator to turn a function into one that returns a `Result`.
        """

        @functools.wraps(f)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T, TE]:
            try:
                return Ok(f(*args, **kwargs))
            except exceptions as exc:
                return Err(exc)

        return wrapper

    return decorator


def as_async_result(
    *exceptions: Type[TE],
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[Result[T, TE]]]]:
    """
    Make a decorator to turn an async function into one that returns a `Result`.
    Regular return values are turned into `Ok(return_value)`. Raised
    exceptions of the specified exception type(s) are turned into `Err(exc)`.
    """
    if not exceptions or not all(
        inspect.isclass(exception) and issubclass(exception, BaseException)
        for exception in exceptions
    ):
        raise TypeError("as_result() requires one or more exception types")

    def decorator(
        f: Callable[P, Awaitable[T]]
    ) -> Callable[P, Awaitable[Result[T, TE]]]:
        """
        Decorator to turn a function into one that returns a `Result`.
        """

        @functools.wraps(f)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T, TE]:
            try:
                return Ok(await f(*args, **kwargs))
            except exceptions as exc:
                return Err(exc)

        return async_wrapper

    return decorator


def is_ok(result: Result[T, E]) -> TypeIs[Ok[T]]:
    """A type guard to check if a result is an Ok

    Usage:

    `` python
    r: Result[int, str] = get_a_result()
    if is_ok(r):
        r   # r is of type Ok[int]
    elif is_err(r):
        r   # r is of type Err[str]
    ``

    """
    return result.is_ok()


def is_err(result: Result[T, E]) -> TypeIs[Err[E]]:
    """A type guard to check if a result is an Err

    Usage:

    `` python
    r: Result[int, str] = get_a_result()
    if is_ok(r):
        r   # r is of type Ok[int]
    elif is_err(r):
        r   # r is of type Err[str]
    ``

    """
    return result.is_err()
