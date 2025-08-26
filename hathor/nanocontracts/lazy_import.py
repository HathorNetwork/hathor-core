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

from typing import TYPE_CHECKING, Callable, Generic, ParamSpec, TypeVar, final

if TYPE_CHECKING:
    from hathor.nanocontracts import Runner


P = ParamSpec('P')
T = TypeVar('T', covariant=True)


@final
class LazyImport(Generic[P, T]):
    """
    A class for imports that are lazy, that is, that cannot be created statically because they depend on a Runner,
    which is only available in runtime during nano executions.
    """
    __slots__ = ('__name', '__create_func', '__runner')

    def __init__(self, name: str, create_func: Callable[[Runner], Callable[P, T]]) -> None:
        self.__name = name
        self.__create_func = create_func

        # This runner must NOT be used by normal code, only in tests. Use the `create_with_runner` method instead.
        # View the `__call__` method for more info.
        self.__runner: Runner | None = None

    def create_with_runner(self, runner: Runner | None) -> Callable[P, T]:
        """
        Create the respective import func with the provided Runner.
        The returned callable will replace the imported function in runtime.
        """
        if runner is not None:
            # Happy path, this might happen during contract execution, when a
            # Runner is available and used to instantiate the lazy import func.
            return self.__create_func(runner)

        # When there's no Runner, the import is replaced with a function that raises an exception
        # to represent an unsupported import.
        # This might happen for example during verification, when a Blueprint class is created
        # (and therefore its imports are retrieved), but there's no Runner to actually instantiate
        # the lazy import. This means lazy imports can never be called at the module-level of
        # blueprints, only in method calls.
        def unsupported(*args: P.args, **kwargs: P.kwargs) -> T:
            raise ImportError(
                f'`{self.__name}` cannot be called without a runtime, probably outside a method call'
            )

        return unsupported

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> T:
        """
        This method is only defined for compatibility with tests and must NOT be used in normal code.
        It'll raise an AssertionError because `self.__runner` must never be set outside of tests.

        Since tests often use ad-hoc blueprint classes that are set directly in the NCCatalog, lazy imports for
        these blueprints will be loaded in "compile-time", meaning they won't call `create_with_runner` because
        they won't go through the normal OCB loading path. Then, tests must set the `__runner` attribute with
        the respective test runner before executing nano contracts, which will call this method directly instead
        of the callable returned by `create_with_runner`.
        """
        assert self.__runner is not None
        func = self.create_with_runner(self.__runner)
        return func(*args, **kwargs)
