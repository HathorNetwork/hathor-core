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

from typing import TYPE_CHECKING, Any, Sequence, assert_never, final

from hathor.nanocontracts.blueprint import NC_FIELDS_ATTR
from hathor.nanocontracts.faux_immutable import FauxImmutable, __set_faux_immutable__
from hathor.nanocontracts.types import (
    NC_FALLBACK_METHOD,
    NC_INITIALIZE_METHOD,
    NC_METHOD_TYPE_ATTR,
    ContractId,
    NCAction,
    NCMethodType,
)

if TYPE_CHECKING:
    from hathor.nanocontracts import Runner


_FORBIDDEN_METHODS = frozenset({NC_INITIALIZE_METHOD, NC_FALLBACK_METHOD})


@final
class ContractAccessor(FauxImmutable):
    """
    This class represents a "proxy contract instance", or a contract accessor, during a blueprint method execution.
    Calling custom blueprint methods on this class will forward the call to the actual wrapped blueprint via syscalls.
    """
    __slots__ = ('__runner', '__contract_id', '__actions')
    __skip_faux_immutability_validation__ = True  # Needed to implement __getattr__

    def __init__(self, *, runner: Runner, contract_id: ContractId) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__actions: tuple[NCAction, ...] | None

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__actions', None)

    def use_actions(self, *actions: NCAction) -> ContractAccessor:
        """
        Set actions on this instance to be used in the next call to a public method.
        Actions are disposed after a single use, and cannot be set before calling a view method.
        """
        from hathor.nanocontracts import NCFail
        if self.__actions is not None:
            raise NCFail(f'unused actions are already set: {self.__actions}')

        __set_faux_immutable__(self, '__actions', actions)
        return self

    def __getattr__(self, method_name: str) -> ViewMethodAccessor | PublicMethodAccessor:
        """Return the respective method accessor for either a view or public method from the wrapped blueprint."""
        from hathor.nanocontracts import NCFail
        if method_name in _FORBIDDEN_METHODS:
            # Even though this is protected later by the runner, we fail early here.
            raise NCFail(f'cannot call method `{method_name}` directly')

        blueprint_id = self.__runner.get_blueprint_id(self.__contract_id)
        blueprint_class = self.__runner.tx_storage.get_blueprint_class(blueprint_id)

        if method_name in getattr(blueprint_class, NC_FIELDS_ATTR, ()):
            raise NCFail(
                f'`{method_name}` is an attribute, not a method, on blueprint `{blueprint_id.hex()}` '
                f'with class `{blueprint_class.__name__}`'
            )

        method = getattr(blueprint_class, method_name, None)
        if method is None:
            raise NCFail(
                f'unknown method `{method_name}` on blueprint `{blueprint_id.hex()}` '
                f'with class `{blueprint_class.__name__}`'
            )

        method_type = getattr(method, NC_METHOD_TYPE_ATTR, None)
        if method_type is None:
            raise NCFail(
                f'cannot call internal method `{method_name}` on blueprint `{blueprint_id.hex()}` '
                f'with class {blueprint_class.__name__}`'
            )

        assert isinstance(method_type, NCMethodType)
        method_accessor: ViewMethodAccessor | PublicMethodAccessor

        match method_type:
            case NCMethodType.VIEW:
                if self.__actions is not None:
                    raise NCFail(f'cannot call view method `{method_name}` while using actions: {self.__actions}')

                method_accessor = ViewMethodAccessor(
                    runner=self.__runner,
                    contract_id=self.__contract_id,
                    method_name=method_name,
                )

            case NCMethodType.PUBLIC:
                # When `use_actions` is not called, the default behavior is to provide no actions to the call.
                actions = self.__actions or ()

                # We must clear used actions after each use.
                __set_faux_immutable__(self, '__actions', None)

                method_accessor = PublicMethodAccessor(
                    runner=self.__runner,
                    contract_id=self.__contract_id,
                    method_name=method_name,
                    actions=actions,
                )

            case NCMethodType.FALLBACK:  # pragma: no cover
                raise AssertionError('call to fallback must be prevented above')

            case _:  # pragma: no cover
                assert_never(method_type)

        assert self.__actions is None, 'actions must be cleared after each use'
        return method_accessor


@final
class ViewMethodAccessor(FauxImmutable):
    """
    This class represents a "proxy view method", or a view method accessor, during a blueprint method execution.
    It's a callable that will forward the call to the actual wrapped blueprint via syscall.
    It may be used multiple times to call the same method with different arguments.
    """
    __slots__ = ('__runner', '__contract_id', '__method_name')

    def __init__(self, *, runner: Runner, contract_id: ContractId, method_name: str) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__method_name: str

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__method_name', method_name)

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        return self.__runner.syscall_call_another_contract_view_method(
            contract_id=self.__contract_id,
            method_name=self.__method_name,
            args=args,
            kwargs=kwargs,
        )


@final
class PublicMethodAccessor(FauxImmutable):
    """
    This class represents a "proxy public method", or a public method accessor, during a blueprint method execution.
    It's a callable that will forward the call to the actual wrapped blueprint via syscall.
    It can only be used once because it consumes the provided actions after a single use.
    """
    __slots__ = ('__runner', '__contract_id', '__method_name', '__actions', '__is_dirty')

    def __init__(
        self,
        *,
        runner: Runner,
        contract_id: ContractId,
        method_name: str,
        actions: Sequence[NCAction],
    ) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__method_name: str
        self.__actions: Sequence[NCAction]
        self.__is_dirty: bool

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__method_name', method_name)
        __set_faux_immutable__(self, '__actions', actions)
        __set_faux_immutable__(self, '__is_dirty', False)

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        from hathor.nanocontracts import NCFail
        if self.__is_dirty:
            raise NCFail(
                f'accessor for method `{self.__method_name}` was already used, '
                f'you must use the contract instance to call it again'
            )

        __set_faux_immutable__(self, '__is_dirty', True)

        return self.__runner.syscall_call_another_contract_public_method(
            contract_id=self.__contract_id,
            method_name=self.__method_name,
            actions=self.__actions,
            args=args,
            kwargs=kwargs,
        )
