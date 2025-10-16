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

from hathor import BlueprintId, ContractId, NCAction, NCFee
from hathor.nanocontracts import Runner
from hathor.nanocontracts.faux_immutable import FauxImmutable, __set_faux_immutable__


@final
class InitializeMethodAccessor(FauxImmutable):
    """
    This class represents an "initialize method", or an initialize method accessor, during a blueprint method
    execution.
    Calling `initialize()` on it will forward the call to the actual wrapped blueprint via syscall.
    It can only be used once because it consumes the provided actions after a single use.
    """
    __slots__ = (
        '__runner',
        '__blueprint_id',
        '__salt',
        '__actions',
        '__fees',
        '__is_dirty',
    )

    def __init__(
        self,
        *,
        runner: Runner,
        blueprint_id: BlueprintId,
        salt: bytes,
        actions: Sequence[NCAction],
        fees: Sequence[NCFee],
    ) -> None:
        self.__runner: Runner
        self.__blueprint_id: BlueprintId
        self.__salt: bytes
        self.__actions: Sequence[NCAction]
        self.__fees: Sequence[NCFee]
        self.__is_dirty: bool

        __set_faux_immutable__(self, '__runner', runner)
        __set_faux_immutable__(self, '__blueprint_id', blueprint_id)
        __set_faux_immutable__(self, '__salt', salt)
        __set_faux_immutable__(self, '__actions', actions)
        __set_faux_immutable__(self, '__fees', fees)
        __set_faux_immutable__(self, '__is_dirty', False)

    def initialize(self, *args: Any, **kwargs: Any) -> tuple[ContractId, object]:
        """Initialize a new contract."""
        from hathor.nanocontracts import NCFail
        if self.__is_dirty:
            raise NCFail(
                'accessor for initialize method was already used, '
                'you must use `setup_new_contract` to call it again'
            )

        __set_faux_immutable__(self, '__is_dirty', True)

        return self.__runner.syscall_create_another_contract(
            blueprint_id=self.__blueprint_id,
            salt=self.__salt,
            actions=self.__actions,
            fees=self.__fees,
            args=args,
            kwargs=kwargs,
        )
