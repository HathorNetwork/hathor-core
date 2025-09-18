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

from typing import TYPE_CHECKING, Any, Collection, Sequence, final

from hathor.nanocontracts.faux_immutable import FauxImmutable, __set_faux_immutable__
from hathor.nanocontracts.types import BlueprintId, ContractId, NCAction

if TYPE_CHECKING:
    from hathor.nanocontracts import Runner


@final
class ContractAccessor(FauxImmutable):
    """
    This class represents a "proxy contract instance", or a contract accessor, during a blueprint method execution.
    Calling custom blueprint methods on this class will forward the call to the actual wrapped blueprint via syscalls.
    """
    __slots__ = ('__runner', '__contract_id', '__blueprint_ids')

    def __init__(
        self,
        *,
        runner: Runner,
        contract_id: ContractId,
        blueprint_id: BlueprintId | Collection[BlueprintId] | None,
    ) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__blueprint_ids: frozenset[BlueprintId] | None

        blueprint_ids: frozenset[BlueprintId] | None
        match blueprint_id:
            case None:
                blueprint_ids = None
            case bytes():
                blueprint_ids = frozenset({blueprint_id})
            case _:
                blueprint_ids = frozenset(blueprint_id)

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__blueprint_ids', blueprint_ids)

    def view(self) -> Any:
        return PreparedViewCall(
            runner=self.__runner,
            contract_id=self.__contract_id,
            blueprint_ids=self.__blueprint_ids,
        )

    def public(self, *actions: NCAction, forbid_fallback: bool = False) -> Any:
        return PreparedPublicCall(
            runner=self.__runner,
            contract_id=self.__contract_id,
            blueprint_ids=self.__blueprint_ids,
            actions=actions,
            forbid_fallback=forbid_fallback,
        )


@final
class PreparedViewCall(FauxImmutable):
    __slots__ = ('__runner', '__contract_id', '__blueprint_ids')
    __skip_faux_immutability_validation__ = True  # Needed to implement __getattr__

    def __init__(
        self,
        *,
        runner: Runner,
        contract_id: ContractId,
        blueprint_ids: frozenset[BlueprintId] | None,
    ) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__blueprint_ids: frozenset[BlueprintId] | None

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__blueprint_ids', blueprint_ids)

    def __getattr__(self, method_name: str) -> ViewMethodAccessor:
        return ViewMethodAccessor(
            runner=self.__runner,
            contract_id=self.__contract_id,
            blueprint_ids=self.__blueprint_ids,
            method_name=method_name,
        )


@final
class PreparedPublicCall(FauxImmutable):
    __slots__ = ('__runner', '__contract_id', '__blueprint_ids', '__actions', '__forbid_fallback', '__is_dirty')
    __skip_faux_immutability_validation__ = True  # Needed to implement __getattr__

    def __init__(
        self,
        *,
        runner: Runner,
        contract_id: ContractId,
        blueprint_ids: frozenset[BlueprintId] | None,
        actions: Sequence[NCAction],
        forbid_fallback: bool,
    ) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__blueprint_ids: frozenset[BlueprintId] | None
        self.__actions: Sequence[NCAction]
        self.__forbid_fallback: bool
        self.__is_dirty: bool

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__blueprint_ids', blueprint_ids)
        __set_faux_immutable__(self, '__actions', actions)
        __set_faux_immutable__(self, '__forbid_fallback', forbid_fallback)
        __set_faux_immutable__(self, '__is_dirty', False)

    def __getattr__(self, method_name: str) -> PublicMethodAccessor:
        from hathor.nanocontracts import NCFail
        if self.__is_dirty:
            raise NCFail(
                f'prepared public method for contract `{self.__contract_id.hex()}` was already used, '
                f'you must use `public` on the contract to call it again'
            )

        __set_faux_immutable__(self, '__is_dirty', True)

        return PublicMethodAccessor(
            runner=self.__runner,
            contract_id=self.__contract_id,
            blueprint_ids=self.__blueprint_ids,
            method_name=method_name,
            actions=self.__actions,
            forbid_fallback=self.__forbid_fallback,
        )


@final
class ViewMethodAccessor(FauxImmutable):
    """
    This class represents a "proxy view method", or a view method accessor, during a blueprint method execution.
    It's a callable that will forward the call to the actual wrapped blueprint via syscall.
    It may be used multiple times to call the same method with different arguments.
    """
    __slots__ = ('__runner', '__contract_id', '__blueprint_ids', '__method_name')

    def __init__(
        self,
        *,
        runner: Runner,
        contract_id: ContractId,
        blueprint_ids: frozenset[BlueprintId] | None,
        method_name: str,
    ) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__blueprint_ids: frozenset[BlueprintId] | None
        self.__method_name: str

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__blueprint_ids', blueprint_ids)
        __set_faux_immutable__(self, '__method_name', method_name)

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        validate_blueprint_id(
            runner=self.__runner,
            contract_id=self.__contract_id,
            blueprint_ids=self.__blueprint_ids,
        )

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
    __slots__ = (
        '__runner',
        '__contract_id',
        '__blueprint_ids',
        '__method_name',
        '__actions',
        '__forbid_fallback',
        '__is_dirty',
    )

    def __init__(
        self,
        *,
        runner: Runner,
        contract_id: ContractId,
        blueprint_ids: frozenset[BlueprintId] | None,
        method_name: str,
        actions: Sequence[NCAction],
        forbid_fallback: bool,
    ) -> None:
        self.__runner: Runner
        self.__contract_id: ContractId
        self.__blueprint_ids: frozenset[BlueprintId] | None
        self.__method_name: str
        self.__actions: Sequence[NCAction]
        self.__forbid_fallback: bool
        self.__is_dirty: bool

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__contract_id', contract_id)
        __set_faux_immutable__(self, '__blueprint_ids', blueprint_ids)
        __set_faux_immutable__(self, '__method_name', method_name)
        __set_faux_immutable__(self, '__actions', actions)
        __set_faux_immutable__(self, '__forbid_fallback', forbid_fallback)
        __set_faux_immutable__(self, '__is_dirty', False)

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        from hathor.nanocontracts import NCFail
        if self.__is_dirty:
            raise NCFail(
                f'accessor for public method `{self.__method_name}` was already used, '
                f'you must use `public` on the contract to call it again'
            )

        __set_faux_immutable__(self, '__is_dirty', True)

        validate_blueprint_id(
            runner=self.__runner,
            contract_id=self.__contract_id,
            blueprint_ids=self.__blueprint_ids,
        )

        return self.__runner.syscall_call_another_contract_public_method(
            contract_id=self.__contract_id,
            method_name=self.__method_name,
            actions=self.__actions,
            args=args,
            kwargs=kwargs,
            forbid_fallback=self.__forbid_fallback,
        )


def validate_blueprint_id(
    *,
    runner: Runner,
    contract_id: ContractId,
    blueprint_ids: frozenset[BlueprintId] | None,
) -> None:
    """Check whether the blueprint id of a contract matches the expected id(s), raise an exception otherwise."""
    if blueprint_ids is None:
        return

    blueprint_id = runner.get_blueprint_id(contract_id)
    if blueprint_id not in blueprint_ids:
        from hathor.nanocontracts import NCFail
        expected = tuple(sorted(bp.hex() for bp in blueprint_ids))
        raise NCFail(
            f'expected blueprint to be one of `{expected}`, '
            f'got `{blueprint_id.hex()}` for contract `{contract_id.hex()}`'
        )
