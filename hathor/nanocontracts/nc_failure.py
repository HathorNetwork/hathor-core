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

from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeAlias, TypeVar, assert_never, final

from returns.result import Failure, Result, Success

if TYPE_CHECKING:
    from hathor.nanocontracts.types import ContractId


class _BaseNCFailure(ABC):
    __slots__ = ()

    @final
    def to_result(self) -> NCResult[Any]:
        assert isinstance(self, NCFailure)  # type: ignore[misc, arg-type]
        return Failure(self)  # type: ignore[arg-type]

    def __str__(self) -> str:
        return repr(self)


@dataclass(slots=True, frozen=True)
class _BaseMessageNCFailure(_BaseNCFailure):
    msg: str

    def __str__(self) -> str:
        return self.msg


@dataclass(slots=True, frozen=True)
class NCUserFailure(_BaseNCFailure):
    exception: Exception

    def __str__(self) -> str:
        return repr(self.exception)


@dataclass(slots=True, frozen=True)
class NCMethodNotFound(_BaseNCFailure):
    """Raised when a method is not found in a nano contract."""
    method_name: str

    def __str__(self) -> str:
        return f'method `{self.method_name}` not found and no fallback is provided'


@dataclass(slots=True, frozen=True)
class NCViewMethodError(_BaseMessageNCFailure):
    """Raised when a view method changes the state of the contract."""


@dataclass(slots=True, frozen=True)
class NCRecursionError(_BaseNCFailure):
    """Raised when recursion gets too deep."""


@dataclass(slots=True, frozen=True)
class NCNumberOfCallsExceeded(_BaseNCFailure):
    """Raised when the total number of calls have been exceeded."""


@dataclass(slots=True, frozen=True)
class NCInvalidContractId(_BaseMessageNCFailure):
    """Raised when a contract call is invalid."""


@dataclass(slots=True, frozen=True)
class NCInsufficientFunds(_BaseMessageNCFailure):
    """Raised when there is not enough funds to withdrawal from a nano contract."""


@dataclass(slots=True, frozen=True)
class NCInvalidMethodCall(_BaseMessageNCFailure):
    """Raised when a contract calls another contract's invalid method."""


@dataclass(slots=True, frozen=True)
class NCInvalidInitializeMethodCall(_BaseMessageNCFailure):
    """Raised when a contract calls another contract's initialize method."""


@dataclass(slots=True, frozen=True)
class NCInvalidPublicMethodCallFromView(_BaseMessageNCFailure):
    """Raised when a contract calls another contract's initialize method."""


@dataclass(slots=True, frozen=True)
class NCAlreadyInitializedContractError(_BaseNCFailure):
    """Raised when one tries to initialize a contract that has already been initialized."""
    contract_id: ContractId

    def __str__(self) -> str:
        return f'contract {self.contract_id.hex()}'


@dataclass(slots=True, frozen=True)
class NCUninitializedContractError(_BaseMessageNCFailure):
    """Raised when a contract calls a method from an uninitialized contract."""


@dataclass(slots=True, frozen=True)
class NCInvalidSyscall(_BaseMessageNCFailure):
    """Raised when a syscall is invalid."""


@dataclass(slots=True, frozen=True)
class NCTokenAlreadyExists(_BaseNCFailure):
    """Raised when one tries to create a duplicated token."""


@dataclass(slots=True, frozen=True)
class NCForbiddenAction(_BaseMessageNCFailure):
    """Raised when an action is forbidden on a method."""


@dataclass(slots=True, frozen=True)
class NCInvalidAction(_BaseMessageNCFailure):
    """Raised when an action is invalid."""


@dataclass(slots=True, frozen=True)
class NCInvalidContext(_BaseMessageNCFailure):
    """Raised when trying to run a method with an invalid context."""


@dataclass(slots=True, frozen=True)
class BlueprintDoesNotExist(_BaseMessageNCFailure):
    pass


@dataclass(slots=True, frozen=True)
class NCInvalidSeqnum(_BaseMessageNCFailure):
    pass


NCFailure: TypeAlias = (
    NCUserFailure
    | NCMethodNotFound
    | NCViewMethodError
    | NCRecursionError
    | NCInvalidContractId
    | NCInsufficientFunds
    | NCInvalidMethodCall
    | NCInvalidInitializeMethodCall
    | NCInvalidPublicMethodCallFromView
    | NCAlreadyInitializedContractError
    | NCUninitializedContractError
    | NCInvalidSyscall
    | NCTokenAlreadyExists
    | NCForbiddenAction
    | NCInvalidAction
    | NCInvalidContext
    | BlueprintDoesNotExist
    | NCInvalidSeqnum
)


@final
class NCFailureException(Exception):
    __slots__ = ('_nc_failure',)

    def __init__(self, nc_failure: NCFailure) -> None:
        self._nc_failure = nc_failure

    def __str__(self) -> str:
        return f'{type(self._nc_failure).__name__}({self._nc_failure})'

    def get_inner(self) -> NCFailure:
        return self._nc_failure

    def to_result(self) -> NCResult[Any]:
        return Failure(self._nc_failure)


T = TypeVar('T')
NCResult: TypeAlias = Result[T, NCFailure]


def unwrap_or_raise(nc_result: NCResult[T]) -> T:
    match nc_result:
        case Success(value):
            return value
        case Failure(NCUserFailure(e)):
            # TODO: Tweak this so we can support try-except on blueprints
            raise e
        case Failure(e):
            raise NCFailureException(e)
        case _:
            assert_never(nc_result)  # type: ignore[arg-type]
