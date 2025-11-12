# Copyright 2024 Hathor Labs
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

import builtins
import types
from functools import partial
from operator import index
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    Mapping,
    NoReturn,
    Protocol,
    Sequence,
    SupportsIndex,
    TypeVar,
    cast,
    final,
)

from typing_extensions import Self, TypeVarTuple

from hathor.nanocontracts.allowed_imports import ALLOWED_IMPORTS
from hathor.nanocontracts.exception import NCDisabledBuiltinError
from hathor.nanocontracts.faux_immutable import FauxImmutable
from hathor.nanocontracts.types import BLUEPRINT_EXPORT_NAME

T = TypeVar('T')
Ts = TypeVarTuple('Ts')

WRAPPER_ASSIGNMENTS = (
    '__module__',
    '__name__',
    '__qualname__',
    '__doc__',
    '__annotations__',
    '__type_params__',
)

WRAPPER_UPDATES = ('__dict__',)


def _update_wrapper(
    wrapper: T,
    wrapped: T,
    assigned: tuple[str, ...] = WRAPPER_ASSIGNMENTS,
    updated: tuple[str, ...] = WRAPPER_UPDATES,
) -> T:
    """ Behaves like functools.update_wrapper but with the important difference of not creating wrapper.__wrapped__
    """
    for attr in assigned:
        try:
            value = getattr(wrapped, attr)
        except AttributeError:
            pass
        else:
            setattr(wrapper, attr, value)
    for attr in updated:
        value = getattr(wrapper, attr)
        assert isinstance(value, dict), 'expected dict on updated attrs'
        value.update(getattr(wrapped, attr, {}))
    # Return the wrapper so this can be used as a decorator via partial()
    return wrapper


def _wraps(
    wrapped: T,
    assigned: tuple[str, ...] = WRAPPER_ASSIGNMENTS,
    updated: tuple[str, ...] = WRAPPER_UPDATES,
) -> Callable[[T], T]:
    """ Like functools.wraps but with our _update_wrapper
    """
    return partial(_update_wrapper, wrapped=wrapped, assigned=assigned, updated=updated)


@_wraps(builtins.range, updated=tuple())  # type: ignore[arg-type]
@final
class custom_range:
    """ Re-implementation of builtins.range in pure Python, so it will execute purely in Python's VM.

    XXX: @_wraps will replace this docstring's with the original docstring
    """

    __slots__ = ('_start', '_stop', '_step')

    @property
    def start(self) -> int:
        return self._start

    @property
    def stop(self) -> int:
        return self._stop

    @property
    def step(self) -> int:
        return self._step

    def __init__(self, *args: SupportsIndex) -> None:
        match args:
            case [stop]:
                self._start = 0
                self._stop = index(stop)
                self._step = 1
            case [start, stop]:
                self._start = index(start)
                self._stop = index(stop)
                self._step = 1
            case [start, stop, step]:
                self._start = index(start)
                self._stop = index(stop)
                self._step = index(step)
                if self._step == 0:
                    raise ValueError('range() arg 3 must not be zero')
            case _:
                raise TypeError(f'range expected at most 3 arguments, got {len(args)}')

    def __repr__(self):
        match (self._start, self._step):
            case (0, 1):
                return f'range({self._stop})'
            case (_, 1):
                return f'range({self._start}, {self._stop})'
            case _:
                return f'range({self._start}, {self._stop}, {self._step})'

    def count(self, value: int) -> int:
        """rangeobject.count(value) -> integer -- return number of occurrences of value"""
        return 1 if value in self else 0

    def index(self, value: int) -> int:
        """rangeobject.index(value) -> integer -- return index of value.
        Raise ValueError if the value is not present.
        """
        if value not in self:
            raise ValueError(f'{value} is not in range')
        return (value - self._start) // self._step

    def __len__(self) -> int:
        if (self._step > 0 and self._start >= self._stop) or (self._step < 0 and self._start <= self._stop):
            return 0
        if self._step > 0:
            return (self._stop - self._start + self._step - 1) // self._step
        else:
            return (self._start - self._stop - self._step - 1) // -self._step

    def __bool__(self) -> bool:
        return len(self) > 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return False
        return self.start == other.start and self.stop == other.stop and self.step == other.step

    def __hash__(self) -> int:
        return hash((self._start, self._stop, self._step))

    def __contains__(self, value: object) -> bool:
        if not isinstance(value, SupportsIndex):
            return False
        val = index(value)
        if self._step > 0:
            return self._start <= val < self._stop and (val - self._start) % self._step == 0
        else:
            return self._start >= val > self._stop and (val - self._start) % self._step == 0

    def __iter__(self) -> Iterator[int]:
        current = self._start
        while (self._step > 0 and current < self._stop) or (self._step < 0 and current > self._stop):
            yield current
            current += self._step

    def _getitem_int(self, key: SupportsIndex) -> int:
        i = index(key)
        if i < 0:
            i += len(self)
        if i < 0 or i >= len(self):
            raise IndexError('range index out of range')
        return self._start + i * self._step

    def _getitem_slice(self, key: slice) -> Self:
        start, stop, step = key.indices(len(self))
        return type(self)(self._start + start * self._step, self._start + stop * self._step, self._step * step)

    def __getitem__(self, key: SupportsIndex | slice) -> int | Self:
        if isinstance(key, slice):
            return self._getitem_slice(key)
        elif isinstance(key, SupportsIndex):
            return self._getitem_int(key)
        else:
            raise TypeError(f'range indices must be integers or slices, not {type(key).__name__}')

    def __reversed__(self) -> Iterator[int]:
        current = self._start + (len(self) - 1) * self._step
        for _ in type(self)(len(self)):
            yield current
            current -= self._step


class ImportFunction(Protocol):
    def __call__(
        self,
        name: str,
        globals: Mapping[str, object] | None = None,
        locals: Mapping[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> types.ModuleType:
        ...


def _generate_restricted_import_function(allowed_imports: dict[str, dict[str, object]]) -> ImportFunction:
    """Returns a function equivalent to builtins.__import__ but that will only import `allowed_imports`"""
    @_wraps(builtins.__import__)
    def __import__(
        name: str,
        globals: Mapping[str, object] | None = None,
        locals: Mapping[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> types.ModuleType:
        if level != 0:
            raise ImportError('Relative imports are not allowed')
        if not fromlist and name != 'typing':
            # XXX: typing is allowed here because Foo[T] triggers a __import__('typing', fromlist=None) for some reason
            raise ImportError('Only `from ... import ...` imports are allowed')
        if name not in allowed_imports:
            raise ImportError(f'Import from "{name}" is not allowed.')

        # Create a fake module class that will only be returned by this import call
        class FakeModule:
            __slots__ = tuple(fromlist)

        fake_module = FakeModule()
        allowed_fromlist = allowed_imports[name]

        for import_what in fromlist:
            if import_what not in allowed_fromlist:
                raise ImportError(f'Import from "{name}.{import_what}" is not allowed.')

            setattr(fake_module, import_what, allowed_fromlist[import_what])

        # This cast is safe because the only requirement is that the object contains the imported attributes.
        return cast(types.ModuleType, fake_module)

    return __import__


def _generate_disabled_builtin_func(name: str) -> Callable[..., NoReturn]:
    """Generate a function analogous to `func` but that will always raise an exception when called."""
    func = getattr(builtins, name, None)
    # I had to disable it because `exit` does not exist in Jupyter kernel.
    # assert func is not None, f'{name} is None'
    msg = f'The use of `{name}` has been disabled'

    class __Disabled__(FauxImmutable):
        __slots__ = ()

        def __call__(self, *args: Any, **kwargs: Any) -> NoReturn:
            raise NCDisabledBuiltinError(msg)

    return __Disabled__()


@_wraps(builtins.all)
def custom_all(iterable: Iterable[object]) -> bool:
    """ Re-implementation of builtins.all in pure Python, so it will execute purely in Python's VM.

    XXX: @_wraps will replace this docstring's with the original docstring
    """
    for i in iterable:
        if not i:
            return False
    return True


@_wraps(builtins.any)
def custom_any(iterable: Iterable[object]) -> bool:
    """ Re-implementation of builtins.any in pure Python, so it will execute purely in Python's VM.

    XXX: @_wraps will replace this docstring's with the original docstring
    """
    for i in iterable:
        if i:
            return True
    return False


@_wraps(builtins.enumerate)  # type: ignore[arg-type]
def enumerate(iterable: Iterable[T], start: int = 0) -> Iterator[tuple[int, T]]:
    """ Re-implementation of builtins.enumerate in pure Python, so it will execute purely in Python's VM.

    XXX: @_wraps will replace this docstring's with the original docstring
    """
    k = start
    for i in iterable:
        yield (k, i)
        k += 1


@_wraps(builtins.filter)  # type: ignore[arg-type]
def filter(function: None | Callable[[T], object], iterable: Iterable[T]) -> Iterator[T]:
    """ Re-implementation of builtins.filter in pure Python, so it will execute purely in Python's VM.

    XXX: @_wraps will replace this docstring's with the original docstring
    """
    fun = (lambda i: i is not None) if function is None else function
    for i in iterable:
        if fun(i):
            yield i


# list of all builtins that are disabled
DISABLED_BUILTINS: frozenset[str] = frozenset({
    # XXX: async is disabled
    'aiter',

    # XXX: async is disabled
    'anext',

    # XXX: used to call sys.breakpointhook, must not be allowed, or we expose a function that raises an exception
    'breakpoint',

    # XXX: used to compile dynamic code, must not be allowed
    'compile',

    # XXX: might be harmless, but it's a _Printer and printing is disabled
    'copyright',

    # XXX: might be harmless, but it's a _Printer and printing is disabled
    'credits',

    # XXX: used to alter attributes dynamically, must not be allowed
    'delattr',

    # XXX: used to list attributes dynamically, must not be allowed
    'dir',

    # XXX: used to run dynamic code, must not be allowed
    'eval',

    # XXX: used to run dynamic code, must not be allowed
    'exec',

    # XXX: used to raise SystemExit exception to close the process, we could make it raise a NCFail
    'exit',

    # XXX: floats are not allowed in runtime
    # O(1)
    # type float
    'float',

    # XXX: used to dynamically get an attribute, must not be allowed
    'getattr',

    # XXX: used to dynamically list variables in the global scope, we already restrict those, so it might be fine
    'globals',

    # XXX: used to dynamically check if an attribute exists, must not be allowed
    'hasattr',

    # XXX: interactive helper, but interactivity is not allowed
    'help',

    # XXX: used to get the address of an object, which allows a blueprint to not be a pure function
    'id',

    # XXX: interactive input, but interactivity is not allowed
    'input',

    # XXX: could be used to introspect on the objects we provide, disallow it just in case
    'issubclass',

    # XXX: might be harmless, but it's a _Printer and printing is disabled
    'license',

    # XXX: used to dynamically access all local variables, could be fine, but restrict it just in case
    'locals',

    # XXX: used for the low level buffer protocol, disallow it just in case
    'memoryview',

    # XXX: used to open files, which is not allowed, maybe expose a dummy function that always fails
    'open',

    # XXX: used for printing, which is not allowed, we could expose a function that does logging to help with debugging
    'print',

    # XXX: same as exit function
    'quit',

    # XXX: used to dynamically set attributes, must not be allowed
    'setattr',

    # XXX: can be used to inspect an object's attributes, including "private" ones
    'vars',

    # XXX: disallow just in case
    # O(1)
    # __repr__ shortcut
    # (obj: object, /) -> str
    'ascii',

    # XXX: disallow just in case
    # O(1)
    # __repr__ shortcut
    # (obj: object, /) -> str
    'repr',

    # XXX: can be used to hide explicit function calls, not sure if this is a problem
    # O(1)
    # type property
    # (
    #     fget: Callable[[Any], Any] | None = ...,
    #     fset: Callable[[Any, Any], None] | None = ...,
    #     fdel: Callable[[Any], None] | None = ...,
    #     doc: str | None = ...,
    # ) -> property
    'property',

    # XXX: Can be used to get an object's class and its metaclass
    # O(1)
    # type type
    # (o: object, /) -> type
    # (name: str, bases: tuple[type, ...], namespace: dict[str, Any], /, **kwds: Any) -> T(type)
    'type',

    # XXX: Root object which contains dangerous methods such as `__setattr__`
    # O(1)
    # type object
    # () -> object
    'object',

    # XXX: Can be used to get the root `object`
    # O(1)
    # type super
    # (t: Any, obj: Any, /) -> super
    # (t: Any, /) -> super
    # () -> super
    'super',

    # These are not necessary and can't be accessed, so we don't include them.
    '__doc__',
    '__loader__',
    '__package__',
    '__spec__',

    # type complex
    # This is useless for Blueprints.
    'complex',

    # =====================================
    # These are not included in the list because they're not callables, so we should generate
    # disabled functions for them. Also, some of them shouldn't be blocked in the AST.

    # XXX: basic constants, they are considered literals by the language so we don't need to include in builtins.
    # 'False',
    # 'None',
    # 'True',

    # special constant to indicate a method is not implemented
    # see: https://docs.python.org/3/library/constants.html#NotImplemented
    # not necessary, devs should use `NotImplementedError` instead
    # 'NotImplemented',

    # This is the same as writting `...` so it's not necessary
    # 'Ellipsis',
})


# these names aren't allowed in the code, to be checked in the AST only
AST_NAME_BLACKLIST: frozenset[str] = frozenset({
    '__builtins__',
    '__build_class__',
    '__import__',
    *DISABLED_BUILTINS,
})


# list of allowed builtins during execution of an on-chain blueprint code
EXEC_BUILTINS: dict[str, Any] = {
    # XXX: check https://github.com/python/mypy/blob/master/mypy/typeshed/stdlib/builtins.pyi for the full typing
    # XXX: check https://github.com/python/cpython/blob/main/Python/bltinmodule.c for the implementation

    # XXX: required to declare classes
    # O(1)
    # (func: Callable[[], CellType | Any], name: str, /, *bases: Any, metaclass: Any = ..., **kwds: Any) -> Any
    '__build_class__': builtins.__build_class__,

    # XXX: required to do imports
    # XXX: will trigger the execution of the imported module
    # (name: str, globals: Mapping[str, object] | None = None, locals: Mapping[str, object] | None = None,
    #  fromlist: Sequence[str] = (), level: int = 0) -> types.ModuleType
    '__import__': _generate_restricted_import_function(ALLOWED_IMPORTS),

    # XXX: also required to declare classes
    # XXX: this would be '__main__' for a module that is loaded as the main entrypoint, and the module name otherwise,
    # since the blueprint code is adhoc, we could as well expose something else, like '__blueprint__' constant
    '__name__': BLUEPRINT_EXPORT_NAME,

    # make it always True, which is how we'll normally run anyway
    '__debug__': True,

    # O(1)
    # (x: SupportsAbs[T], /) -> T
    'abs': builtins.abs,

    # XXX: consumes an iterable when calling
    # O(N) for N=len(iterable)
    # (iterable: Iterable[object], /) -> bool
    'all': custom_all,

    # XXX: consumes an iterable when calling
    # O(N) for N=len(iterable)
    # (iterable: Iterable[object], /) -> bool
    'any': custom_any,

    # O(1)
    # (number: int | SupportsIndex, /) -> str
    'bin': builtins.bin,

    # O(1)
    # type bool(int)
    'bool': builtins.bool,

    # XXX: consumes an iterable when calling
    # O(N) for N=len(iterable)
    # type bytearray(MutableSequence[int])
    'bytearray': builtins.bytearray,

    # XXX: consumes an iterable when calling
    # O(N) for N=len(iterable)
    # type bytes(Sequence[int])
    'bytes': builtins.bytes,

    # O(1)
    # (obj: object, /) -> bool
    'callable': builtins.callable,

    # O(1)
    # (i: int, /) -> str
    'chr': builtins.chr,

    # O(1)
    # decorator
    'classmethod': builtins.classmethod,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterable)
    # type dict(MutableMapping[K, V])
    # () -> dict
    # (**kwargs: V) -> dict[str, V]
    # (map: SupportsKeysAndGetItem[K, V], /) -> dict[K, V]
    # (map: SupportsKeysAndGetItem[str, V], /, **kwargs: V) -> dict[K, V]
    # (iterable: Iterable[tuple[K, V]], /) -> dict[K, V]
    # (iterable: Iterable[tuple[str, V]], /, **kwargs: V) -> dict[str, V]
    # (iterable: Iterable[list[str]], /) -> dict[str, str]
    # (iterable: Iterable[list[bytes]], /) -> dict[bytes, bytes]
    'dict': builtins.dict,

    # O(1)
    # (x: SupportsDivMod[T, R], y: T, /) -> R
    # (x: T, y: SupportsRDivMod[T, R], /) -> R
    'divmod': builtins.divmod,

    # O(1)
    # (iterable: Iterable[T], start: int = 0) -> enumerate(Iterator[T])
    'enumerate': enumerate,

    # O(1)
    # (function: None, iterable: Iterable[T | None], /) -> filter(Iterator[T])
    # (function: Callable[[S], TypeGuard[T]], iterable: Iterable[S], /) -> filter(Iterator[T])
    # (function: Callable[[S], TypeIs[T]], iterable: Iterable[S], /) -> filter(Iterator[T])
    # (function: Callable[[T], Any], iterable: Iterable[T], /) -> filter(Iterator[T])
    'filter': builtins.filter,

    # O(N) for N=len(value)
    # (value: object, format_spec: str = "", /) -> str
    'format': builtins.format,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterable)
    # type frozenset(AbstractSet[T])
    # () -> frozenset
    # (iterable: Iterable[T], /) -> frozenset[T]
    'frozenset': builtins.frozenset,

    # O(1)
    # __hash__ shortcut
    # (obj: object, /) -> int
    'hash': builtins.hash,

    # O(1)
    # (number: int | SupportsIndex, /) -> str
    'hex': builtins.hex,

    # We allow `isinstance()` checks
    'isinstance': builtins.isinstance,

    # O(1) various -> int
    # (x: ConvertibleToInt = ..., /) -> int
    # (x: str | bytes | bytearray, /, base: SupportsIndex) -> int
    'int': builtins.int,

    # O(1)
    # __iter__ shortcut
    # (object: SupportsIter[I], /) -> I
    # (object: GetItemIterable[T], /) -> Iterator[T]
    # (object: Callable[[], T | None], sentinel: None, /) -> Iterator[T]
    # (object: Callable[[], T], sentinel: object, /) -> Iterator[T]
    'iter': builtins.iter,

    # O(1)
    # (obj: Sized, /) -> int
    'len': builtins.len,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterable)
    # () -> list
    # (iterable: Iterable[T], /) -> list[T]
    'list': builtins.list,

    # O(1)
    # type map
    # (func: Callable[[T], S], iter: Iterable[T], /) -> map[S]
    # (func: Callable[[T1, T2], S], iter1: Iterable[T1], iter2: Iterable[T2], /) -> map[S]
    # ...
    # (func: Callable[[T1, ..., TN], S], iter1: Iterable[T1], ..., iterN: Iterable[TN],/) -> map[S]
    'map': builtins.map,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterables)
    # (arg1: T, arg2: T, /, *_args: T, key: None = None) -> T
    # (arg1: T, arg2: T, /, *_args: T, key: Callable[[T], T]) -> T
    # (iterable: Iterable[T], /, *, key: None = None) -> T
    # (iterable: Iterable[T], /, *, key: Callable[[T], T]) -> T
    # (iterable: Iterable[T], /, *, key: None = None, default: T) -> T
    # (iterable: Iterable[T], /, *, key: Callable[[T], T], default: T) -> T
    'max': builtins.max,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterables)
    # (arg1: T, arg2: T, /, *_args: T, key: None = None) -> T
    # (arg1: T, arg2: T, /, *_args: T, key: Callable[[T], T]) -> T
    # (iterable: Iterable[T], /, *, key: None = None) -> T
    # (iterable: Iterable[T], /, *, key: Callable[[T], T]) -> T
    # (iterable: Iterable[T], /, *, key: None = None, default: T) -> T
    # (iterable: Iterable[T], /, *, key: Callable[[T], T], default: T) -> T
    'min': builtins.min,

    # O(1)
    # __next__ shortcut
    # (i: SupportsNext[T], /) -> T
    # (i: SupportsNext[T], default: V, /) -> T | V
    'next': builtins.next,

    # O(1)
    # (number: int | SupportsIndex, /) -> str
    'oct': builtins.oct,

    # O(1)
    # (c: str | bytes | bytearray, /) -> int
    'ord': builtins.ord,

    # XXX: can be used to easily make large numbers
    # O(1)
    # (base: int, exp: int, mod: int) -> int
    'pow': builtins.pow,

    # XXX: generator that escapes the VM
    # O(1)
    # type range(Sequence[int])
    # (stop: SupportsIndex, /) -> range
    # (start: SupportsIndex, stop: SupportsIndex, step: SupportsIndex = ..., /) -> range
    'range': custom_range,

    # XXX: can consume an iterator when calling
    # O(N) for N=len(sequence)
    # type reversed(Iterator[T])
    # (sequence: Reversible[T], /) -> reversed[T]
    # (sequence: SupportsLenAndGetItem[T], /) -> reversed[T]
    'reversed': builtins.reversed,

    # O(1)
    # (number: SupportsRound1[T], ndigits: None = None) -> T
    # (number: SupportsRound2[T], ndigits: SupportsIndex) -> T
    'round': builtins.round,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterable)
    # type set(MutableSet[T])
    # () -> set
    # (iterable: Iterable[T], /) -> set[T]
    'set': builtins.set,

    # O(1)
    # type slice(Generic[A, B, C])
    # (stop: int | None, /) -> slice[int | MaybeNone, int | MaybeNone, int | MaybeNone]
    'slice': builtins.slice,

    # XXX: consumes an iterator when calling
    # O(N*log(N)) for N=len(iterable)
    # (iterable: Iterable[T], /, *, key: None = None, reverse: bool = False) -> list[T]
    # (iterable: Iterable[T], /, *, key: Callable[[T], T], reverse: bool = False) -> list[T]
    'sorted': builtins.sorted,

    # O(1)
    # type staticmethod(Generic[P, R])
    # (f: Callable[P, R], /) -> staticmethod[P, R]
    'staticmethod': builtins.staticmethod,

    # O(1)
    # __str__ shortcut
    # (object: object = ...) -> str
    # (object: ReadableBuffer, encoding: str = ..., errors: str = ...) -> str
    'str': builtins.str,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterable)
    # (iterable: Iterable[bool], /, start: int = 0) -> int
    # (iterable: Iterable[T], /) -> T
    # (iterable: Iterable[T], /, start: T) -> T
    'sum': builtins.sum,

    # XXX: consumes an iterator when calling
    # O(N) for N=len(iterable)
    # type tuple(Sequence[T])
    # (iterable: Iterable[T] = ..., /) -> tuple[T]
    'tuple': builtins.tuple,

    # O(1)
    # type zip(Iterator[T])
    # (iter: Iterable[T], /, *, strict: bool = ...) -> zip[tuple[T]]
    # (iter1: Iterable[T1], iter2: Iterable[T2], /, *, strict: bool = ...) -> zip[tuple[T1, T2]]
    # ...
    # (iter1: Iterable[T1], ..., iterN: Iterable[TN], /, *, strict: bool = ...) -> zip[tuple[T1, ..., TN]]
    'zip': builtins.zip,

    # these exceptions aren't available in Python 3.10, so don't expose them
    # 'BaseExceptionGroup': builtins.BaseExceptionGroup,
    # 'ExceptionGroup': builtins.ExceptionGroup,

    # expose all other exception types:
    'ArithmeticError': builtins.ArithmeticError,
    'AssertionError': builtins.AssertionError,
    'AttributeError': builtins.AttributeError,
    'BaseException': builtins.BaseException,
    'BlockingIOError': builtins.BlockingIOError,
    'BrokenPipeError': builtins.BrokenPipeError,
    'BufferError': builtins.BufferError,
    'ChildProcessError': builtins.ChildProcessError,
    'ConnectionAbortedError': builtins.ConnectionAbortedError,
    'ConnectionError': builtins.ConnectionError,
    'ConnectionRefusedError': builtins.ConnectionRefusedError,
    'ConnectionResetError': builtins.ConnectionResetError,
    'EOFError': builtins.EOFError,
    'EnvironmentError': builtins.EnvironmentError,
    'Exception': builtins.Exception,
    'FileExistsError': builtins.FileExistsError,
    'FileNotFoundError': builtins.FileNotFoundError,
    'FloatingPointError': builtins.FloatingPointError,
    'GeneratorExit': builtins.GeneratorExit,
    'IOError': builtins.IOError,
    'ImportError': builtins.ImportError,
    'IndentationError': builtins.IndentationError,
    'IndexError': builtins.IndexError,
    'InterruptedError': builtins.InterruptedError,
    'IsADirectoryError': builtins.IsADirectoryError,
    'KeyError': builtins.KeyError,
    'KeyboardInterrupt': builtins.KeyboardInterrupt,
    'LookupError': builtins.LookupError,
    'MemoryError': builtins.MemoryError,
    'ModuleNotFoundError': builtins.ModuleNotFoundError,
    'NameError': builtins.NameError,
    'NotADirectoryError': builtins.NotADirectoryError,
    'NotImplementedError': builtins.NotImplementedError,
    'OSError': builtins.OSError,
    'OverflowError': builtins.OverflowError,
    'PermissionError': builtins.PermissionError,
    'ProcessLookupError': builtins.ProcessLookupError,
    'RecursionError': builtins.RecursionError,
    'ReferenceError': builtins.ReferenceError,
    'RuntimeError': builtins.RuntimeError,
    'StopAsyncIteration': builtins.StopAsyncIteration,
    'StopIteration': builtins.StopIteration,
    'SyntaxError': builtins.SyntaxError,
    'SystemError': builtins.SystemError,
    'SystemExit': builtins.SystemExit,
    'TabError': builtins.TabError,
    'TimeoutError': builtins.TimeoutError,
    'TypeError': builtins.TypeError,
    'UnboundLocalError': builtins.UnboundLocalError,
    'UnicodeDecodeError': builtins.UnicodeDecodeError,
    'UnicodeEncodeError': builtins.UnicodeEncodeError,
    'UnicodeError': builtins.UnicodeError,
    'UnicodeTranslateError': builtins.UnicodeTranslateError,
    'ValueError': builtins.ValueError,
    'ZeroDivisionError': builtins.ZeroDivisionError,

    # expose all warning types:
    'BytesWarning': builtins.BytesWarning,
    'DeprecationWarning': builtins.DeprecationWarning,
    'EncodingWarning': builtins.EncodingWarning,
    'FutureWarning': builtins.FutureWarning,
    'ImportWarning': builtins.ImportWarning,
    'PendingDeprecationWarning': builtins.PendingDeprecationWarning,
    'ResourceWarning': builtins.ResourceWarning,
    'RuntimeWarning': builtins.RuntimeWarning,
    'SyntaxWarning': builtins.SyntaxWarning,
    'UnicodeWarning': builtins.UnicodeWarning,
    'UserWarning': builtins.UserWarning,
    'Warning': builtins.Warning,

    # All other builtins are NOT exposed:
    # =====================================

    **{
        name: _generate_disabled_builtin_func(name)
        for name in DISABLED_BUILTINS
    },
}
