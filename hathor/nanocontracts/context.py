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

from collections import defaultdict
from itertools import chain
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Sequence, final

from hathor.crypto.util import get_address_b58_from_bytes
from hathor.nanocontracts.exception import NCFail, NCInvalidContext
from hathor.nanocontracts.types import Address, ContractId, NCAction, TokenUid
from hathor.nanocontracts.vertex_data import VertexData
from hathor.transaction.exceptions import TxValidationError

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction

_EMPTY_MAP: MappingProxyType[TokenUid, tuple[NCAction, ...]] = MappingProxyType({})


@final
class Context:
    """Context passed to a method call. An empty list of actions means the
    method is being called with no deposits and withdrawals.

    Deposits and withdrawals are grouped by token. Note that it is impossible
    to have both a deposit and a withdrawal for the same token.
    """
    __slots__ = ('__actions', '__address', '__vertex', '__timestamp', '__all_actions__')
    __actions: MappingProxyType[TokenUid, tuple[NCAction, ...]]
    __address: Address | ContractId
    __vertex: VertexData
    __timestamp: int

    def __init__(
        self,
        actions: Sequence[NCAction],
        vertex: BaseTransaction | VertexData,
        address: Address | ContractId,
        timestamp: int,
    ) -> None:
        # Dict of action where the key is the token_uid.
        # If empty, it is a method call without any actions.
        if not actions:
            self.__actions = _EMPTY_MAP
        else:
            from hathor.verification.nano_header_verifier import NanoHeaderVerifier
            try:
                NanoHeaderVerifier.verify_action_list(actions)
            except TxValidationError as e:
                raise NCInvalidContext('invalid nano context') from e

            actions_map: defaultdict[TokenUid, tuple[NCAction, ...]] = defaultdict(tuple)
            for action in actions:
                actions_map[action.token_uid] = (*actions_map[action.token_uid], action)
            self.__actions = MappingProxyType(actions_map)

        self.__all_actions__: tuple[NCAction, ...] = tuple(chain(*self.__actions.values()))

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
    def actions(self) -> MappingProxyType[TokenUid, tuple[NCAction, ...]]:
        """Get a mapping of actions per token."""
        return self.__actions

    @property
    def actions_list(self) -> Sequence[NCAction]:
        """Get a list of all actions."""
        return tuple(self.__all_actions__)

    def get_single_action(self, token_uid: TokenUid) -> NCAction:
        """Get exactly one action for the provided token, and fail otherwise."""
        actions = self.actions.get(token_uid)
        if actions is None or len(actions) != 1:
            raise NCFail(f'expected exactly 1 action for token {token_uid.hex()}')
        return actions[0]

    def copy(self) -> Context:
        """Return a copy of the context."""
        return Context(
            actions=list(self.__all_actions__),
            vertex=self.vertex,
            address=self.address,
            timestamp=self.timestamp,
        )

    def to_json(self) -> dict[str, Any]:
        """Return a JSON representation of the context."""
        return {
            'actions': [action.to_json() for action in self.__all_actions__],
            'address': get_address_b58_from_bytes(self.address),
            'timestamp': self.timestamp,
        }
