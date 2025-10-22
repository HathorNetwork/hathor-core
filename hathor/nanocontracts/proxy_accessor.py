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
    """
    This class represents a "proxy instance", or a proxy accessor, during a blueprint method execution.
    Calling custom blueprint methods on this class will forward the call to the actual wrapped blueprint via syscalls.
    """
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

    def view(self) -> Any:
        """Prepare a call to a proxy view method."""
        return PreparedProxyViewCall(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
        )

    def public(self, *actions: NCAction, fees: Sequence[NCFee] | None = None, forbid_fallback: bool = False) -> Any:
        """Prepare a proxy call to a public method."""
        return PreparedProxyPublicCall(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
            actions=actions,
            fees=fees or (),
            forbid_fallback=forbid_fallback,
        )

    def get_view_method(self, method_name: str) -> ProxyViewMethodAccessor:
        """Get a proxy view method."""
        return ProxyViewMethodAccessor(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
            method_name=method_name,
        )

    def get_public_method(
        self,
        method_name: str,
        *actions: NCAction,
        fees: Sequence[NCFee] | None = None,
        forbid_fallback: bool = False,
    ) -> ProxyPublicMethodAccessor:
        """Get a proxy public method."""
        return ProxyPublicMethodAccessor(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
            method_name=method_name,
            actions=actions,
            fees=fees or (),
            forbid_fallback=forbid_fallback,
        )


@final
class PreparedProxyViewCall(FauxImmutable):
    __slots__ = ('__runner', '__blueprint_id')
    __skip_faux_immutability_validation__ = True  # Needed to implement __getattr__

    def __init__(self, *, runner: Runner, blueprint_id: BlueprintId) -> None:
        self.__runner: Runner
        self.__blueprint_id: BlueprintId

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__blueprint_id', blueprint_id)

    def __getattr__(self, method_name: str) -> ProxyViewMethodAccessor:
        return ProxyViewMethodAccessor(
            runner=self.__runner,
            blueprint_id=self.__blueprint_id,
            method_name=method_name,
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
class ProxyViewMethodAccessor(FauxImmutable):
    """
    This class represents a "proxy view method", or a proxy view method accessor, during a blueprint method execution.
    It's a callable that will forward the call to the actual wrapped blueprint via syscall.
    It may be used multiple times to call the same method with different arguments.
    """
    __slots__ = ('__runner', '__blueprint_id', '__method_name')

    def __init__(self, *, runner: Runner, blueprint_id: BlueprintId, method_name: str) -> None:
        self.__runner: Runner
        self.__blueprint_id: BlueprintId
        self.__method_name: str

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__blueprint_id', blueprint_id)
        __set_faux_immutable__(self, '__method_name', method_name)

    def call(self, *args: Any, **kwargs: Any) -> object:
        """Call the method with the provided arguments. This is just an alias for calling the object directly."""
        return self(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        """Call the method with the provided arguments."""
        return self.__runner.syscall_proxy_call_view_method(
            blueprint_id=self.__blueprint_id,
            method_name=self.__method_name,
            args=args,
            kwargs=kwargs,
        )


@final
class ProxyPublicMethodAccessor(FauxImmutable):
    """
    This class represents a "proxy public method", or a proxy public method accessor, during a blueprint method
    execution.
    It's a callable that will forward the call to the actual wrapped blueprint via syscall.
    It can only be used once because it consumes the provided actions after a single use.
    """
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
        """Call the method with the provided arguments. This is just an alias for calling the object directly."""
        return self(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        """Call the method with the provided arguments."""
        nc_args = NCParsedArgs(args, kwargs)
        return self.call_with_nc_args(nc_args)

    def call_with_nc_args(self, nc_args: NCArgs) -> object:
        """Call the method with the provided NCArgs."""
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
