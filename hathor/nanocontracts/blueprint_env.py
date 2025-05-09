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

from typing import TYPE_CHECKING, Any, Optional, final

from hathor.nanocontracts.storage import NCContractStorage
from hathor.nanocontracts.types import BlueprintId, ContractId, NCAction, TokenUid

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogger
    from hathor.nanocontracts.rng import NanoRNG
    from hathor.nanocontracts.runner import Runner


class BlueprintEnvironment:
    """A class that holds all possible interactions a blueprint may have with the system."""

    __slots__ = ('__log__', '__runner', '__storage__', '__cache__')

    def __init__(self, runner: Runner, storage: NCContractStorage, nc_logger: NCLogger) -> None:
        self.__log__ = nc_logger
        self.__runner = runner
        self.__storage__ = storage
        self.__cache__: dict[str, Any] = {}

    @final
    @property
    def rng(self) -> NanoRNG:
        """Return an RNG for the current contract."""
        return self.__runner.get_rng()

    @final
    def get_contract_id(self) -> ContractId:
        """Return the current contract id."""
        return self.__runner.get_current_contract_id()

    @final
    def get_blueprint_id(self, nanocontract_id: Optional[ContractId] = None) -> BlueprintId:
        """Return the blueprint id of a nano contract. By default, it returns for the current contract."""
        if nanocontract_id is None:
            nanocontract_id = self.get_contract_id()
        return self.__runner.get_blueprint_id(nanocontract_id)

    @final
    def get_balance(
        self,
        token_uid: Optional[TokenUid] = None,
        *,
        nanocontract_id: Optional[ContractId] = None,
    ) -> int:
        """Return the balance for a given token without considering the current transaction.

        For instance, if a contract has 50 HTR and a transaction is requesting to withdraw 3 HTR,
        then this method will return 50 HTR."""
        return self.__runner.get_balance(nanocontract_id, token_uid)

    @final
    def call_public_method(
        self,
        nc_id: ContractId,
        method_name: str,
        actions: list[NCAction],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call a public method of another contract."""
        return self.__runner.call_another_contract_public_method(nc_id, method_name, actions, *args, **kwargs)

    @final
    def call_view_method(self, nc_id: ContractId, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a view method of another contract."""
        return self.__runner.call_view_method(nc_id, method_name, *args, **kwargs)

    @final
    def create_contract(
        self,
        blueprint_id: BlueprintId,
        salt: bytes,
        actions: list[NCAction],
        *args: Any,
        **kwargs: Any,
    ) -> tuple[ContractId, Any]:
        """Create a new contract."""
        return self.__runner.create_another_contract(blueprint_id, salt, actions, *args, **kwargs)

    @final
    def emit_event(self, data: bytes) -> None:
        """Emit a custom event from a Nano Contract."""
        self.__log__.__emit_event__(data)
