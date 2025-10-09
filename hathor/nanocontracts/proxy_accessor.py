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

from typing import Any, Sequence, final

from hathor import BlueprintId, NCAction, NCArgs, NCFee, NCParsedArgs
from hathor.nanocontracts import Runner
from hathor.nanocontracts.faux_immutable import FauxImmutable, __set_faux_immutable__


@final
class ProxyAccessor(FauxImmutable):
    __slots__ = ('__runner', '__blueprint_id')

    def __init__(
        self,
        *,
        runner: Runner,
        blueprint_id: BlueprintId,
    ) -> None:
        self.__runner: Runner
        self.__blueprint_id: BlueprintId

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__blueprint_id', blueprint_id)

    def get_blueprint_id(self) -> BlueprintId:
        """Return the blueprint id of this proxy."""
        return self.__blueprint_id

    def public(self, *actions: NCAction, fees: Sequence[NCFee] | None = None, forbid_fallback: bool = False) -> Any:
        return PreparedProxyPublicCall(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
            actions=actions,
            fees=fees or (),
            forbid_fallback=forbid_fallback,
        )

    def get_public_method(
        self,
        method_name: str,
        *actions: NCAction,
        fees: Sequence[NCFee] | None = None,
        forbid_fallback: bool = False,
    ) -> ProxyPublicMethodAccessor:
        return ProxyPublicMethodAccessor(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
            method_name=method_name,
            actions=actions,
            fees=fees or (),
            forbid_fallback=forbid_fallback,
        )


@final
class PreparedProxyPublicCall(FauxImmutable):
    __slots__ = (
        '__runner',
        '__blueprint_id',
        '__actions',
        '__fees',
        '__forbid_fallback',
        '__is_dirty',
    )
    __skip_faux_immutability_validation__ = True  # Needed to implement __getattr__

    def __init__(
        self,
        *,
        runner: Runner,
        blueprint_id: BlueprintId,
        actions: Sequence[NCAction],
        fees: Sequence[NCFee],
        forbid_fallback: bool,
    ) -> None:
        self.__runner: Runner
        self.__blueprint_id: BlueprintId
        self.__actions: Sequence[NCAction]
        self.__fees: Sequence[NCFee]
        self.__forbid_fallback: bool
        self.__is_dirty: bool

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__blueprint_id', blueprint_id)
        __set_faux_immutable__(self, '__actions', actions)
        __set_faux_immutable__(self, '__fees', fees)
        __set_faux_immutable__(self, '__forbid_fallback', forbid_fallback)
        __set_faux_immutable__(self, '__is_dirty', False)

    def __getattr__(self, method_name: str) -> ProxyPublicMethodAccessor:
        from hathor.nanocontracts import NCFail
        if self.__is_dirty:
            raise NCFail(
                f'prepared proxy public method for blueprint `{self.__blueprint_id.hex()}` was already used, '
                f'you must use `public` on the proxy to call it again'
            )

        __set_faux_immutable__(self, '__is_dirty', True)

        return ProxyPublicMethodAccessor(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
            method_name=method_name,
            actions=self.__actions,
            fees=self.__fees,
            forbid_fallback=self.__forbid_fallback,
        )


@final
class ProxyPublicMethodAccessor(FauxImmutable):
    __slots__ = (
        '__runner',
        '__blueprint_id',
        '__method_name',
        '__actions',
        '__fees',
        '__forbid_fallback',
        '__is_dirty',
    )

    def __init__(
        self,
        *,
        runner: Runner,
        blueprint_id: BlueprintId,
        method_name: str,
        actions: Sequence[NCAction],
        fees: Sequence[NCFee],
        forbid_fallback: bool,
    ) -> None:
        self.__runner: Runner
        self.__blueprint_id: BlueprintId
        self.__method_name: str
        self.__actions: Sequence[NCAction]
        self.__fees: Sequence[NCFee]
        self.__forbid_fallback: bool
        self.__is_dirty: bool

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__blueprint_id', blueprint_id)
        __set_faux_immutable__(self, '__method_name', method_name)
        __set_faux_immutable__(self, '__actions', actions)
        __set_faux_immutable__(self, '__fees', fees)
        __set_faux_immutable__(self, '__forbid_fallback', forbid_fallback)
        __set_faux_immutable__(self, '__is_dirty', False)

    def call(self, *args: Any, **kwargs: Any) -> object:
        return self(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        nc_args = NCParsedArgs(args, kwargs)
        return self.call_with_nc_args(nc_args)

    def call_with_nc_args(self, nc_args: NCArgs) -> object:
        from hathor.nanocontracts import NCFail
        if self.__is_dirty:
            raise NCFail(
                f'accessor for proxy public method `{self.__method_name}` was already used, '
                f'you must use `public`/`public_method` on the proxy to call it again'
            )

        __set_faux_immutable__(self, '__is_dirty', True)

        return self.__runner.syscall_proxy_call_public_method(
            blueprint_id=self.__blueprint_id,
            method_name=self.__method_name,
            actions=self.__actions,
            fees=self.__fees,
            nc_args=nc_args,
            forbid_fallback=self.__forbid_fallback,
        )
