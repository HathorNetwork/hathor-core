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
from typing import TYPE_CHECKING, Any

from hathor.crypto.util import get_address_b58_from_bytes
from hathor.nanocontracts.exception import NCInvalidContext
from hathor.nanocontracts.types import Address, ContractId, NCAction, TokenUid
from hathor.nanocontracts.vertex_data import VertexData
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:
    from hathor.nanocontracts.runner import Runner


class Context:
    """Context passed to a method call. An empty list of actions means the
    method is being called with no deposits and withdrawals.

    Deposits and withdrawals are grouped by token. Note that it is impossible
    to have both a deposit and a withdrawal for the same token.
    """
    _runner: Runner | None

    def __init__(self,
                 actions: list[NCAction],
                 vertex: BaseTransaction | VertexData,
                 address: Address | ContractId, timestamp: int) -> None:
        # Dict of action where the key is the token_uid.
        # If empty, it is a method call without deposits and withdrawals.
        actions_map: dict[TokenUid, NCAction] = {}
        for action in actions:
            if action.token_uid in actions_map:
                raise NCInvalidContext('Two or more actions with the same token uid')
            actions_map[action.token_uid] = action
        self.actions = MappingProxyType(actions_map)

        # Vertex calling the method.
        self.vertex: VertexData
        if isinstance(vertex, VertexData):
            self.vertex = vertex
        else:
            self.vertex = VertexData.create_from_vertex(vertex)

        # Address calling the method.
        self.address = address

        # Timestamp of the first block confirming tx.
        self.timestamp = timestamp

    def copy(self) -> 'Context':
        """Return a copy of the context."""
        ctx = Context(
            actions=[],
            vertex=self.vertex,
            address=self.address,
            timestamp=self.timestamp,
        )
        ctx.actions = MappingProxyType(self.actions)
        return ctx

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
