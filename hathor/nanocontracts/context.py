# Copyright 2023 Hathor Labs
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

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Any, final

from hathor.crypto.util import get_address_b58_from_bytes
from hathor.nanocontracts.exception import NCInvalidContext
from hathor.nanocontracts.types import Address, ContractId, NCAction, TokenUid
from hathor.nanocontracts.vertex_data import VertexData

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction

_EMPTY_MAP: MappingProxyType[TokenUid, NCAction] = MappingProxyType({})


@final
class Context:
    """Context passed to a method call. An empty list of actions means the
    method is being called with no deposits and withdrawals.

    Deposits and withdrawals are grouped by token. Note that it is impossible
    to have both a deposit and a withdrawal for the same token.
    """
    __slots__ = ('__actions', '__address', '__vertex', '__timestamp')
    __actions: MappingProxyType[TokenUid, NCAction]
    __address: Address | ContractId
    __vertex: VertexData
    __timestamp: int

    def __init__(
        self,
        actions: list[NCAction] | MappingProxyType[TokenUid, NCAction],
        vertex: BaseTransaction | VertexData,
        address: Address | ContractId,
        timestamp: int,
    ) -> None:
        # Dict of action where the key is the token_uid.
        # If empty, it is a method call without deposits and withdrawals.
        if isinstance(actions, MappingProxyType):
            self.__actions = actions
        elif not actions:
            self.__actions = _EMPTY_MAP
        else:
            actions_map: dict[TokenUid, NCAction] = {}
            for action in actions:
                if action.token_uid in actions_map:
                    raise NCInvalidContext('Two or more actions with the same token uid')
                actions_map[action.token_uid] = action
            self.__actions = MappingProxyType(actions_map)

        # Vertex calling the method.
        if isinstance(vertex, VertexData):
            self.__vertex = vertex
        else:
            self.__vertex = VertexData.create_from_vertex(vertex)

        # Address calling the method.
        self.__address = address

        # Timestamp of the first block confirming tx.
        self.__timestamp = timestamp

    @property
    def vertex(self) -> VertexData:
        return self.__vertex

    @property
    def address(self) -> Address | ContractId:
        return self.__address

    @property
    def timestamp(self) -> int:
        return self.__timestamp

    @property
    def actions(self) -> MappingProxyType[TokenUid, NCAction]:
        return self.__actions

    def copy(self) -> Context:
        """Return a copy of the context."""
        return Context(
            actions=self.actions,
            vertex=self.vertex,
            address=self.address,
            timestamp=self.timestamp,
        )

    def to_json(self) -> dict[str, Any]:
        """Return a JSON representation of the context."""
        return {
            'actions': [{
                'type': action.type.value,
                'token_uid': action.token_uid.hex(),
                'amount': action.amount,
            } for token_uid, action in self.actions.items()],
            'address': get_address_b58_from_bytes(self.address),
            'timestamp': self.timestamp,
        }
