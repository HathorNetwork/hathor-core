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
from typing import TYPE_CHECKING, Any, Sequence, assert_never, final

from hathor.crypto.util import get_address_b58_from_bytes
from hathor.nanocontracts.exception import NCFail, NCInvalidContext
from hathor.nanocontracts.types import Address, CallerId, ContractId, NCAction, TokenUid
from hathor.nanocontracts.vertex_data import BlockData, VertexData
from hathor.transaction.exceptions import TxValidationError

if TYPE_CHECKING:
    from hathor.transaction import Vertex

_EMPTY_MAP: MappingProxyType[TokenUid, tuple[NCAction, ...]] = MappingProxyType({})


@final
class Context:
    """Context passed to a method call. An empty list of actions means the
    method is being called with no deposits and withdrawals.

    Deposits and withdrawals are grouped by token. Note that it is impossible
    to have both a deposit and a withdrawal for the same token.
    """
    __slots__ = ('__actions', '__caller_id', '__vertex', '__block', '__all_actions__')
    __caller_id: CallerId
    __vertex: VertexData
    __block: BlockData | None
    __actions: MappingProxyType[TokenUid, tuple[NCAction, ...]]

    @staticmethod
    def __group_actions__(actions: Sequence[NCAction]) -> MappingProxyType[TokenUid, tuple[NCAction, ...]]:
        actions_map: defaultdict[TokenUid, tuple[NCAction, ...]] = defaultdict(tuple)
        for action in actions:
            actions_map[action.token_uid] = (*actions_map[action.token_uid], action)
        return MappingProxyType(actions_map)

    @classmethod
    def create_from_vertex(
        cls,
        *,
        caller_id: CallerId,
        vertex: Vertex,
        actions: Sequence[NCAction],
    ) -> Context:
        # Dict of action where the key is the token_uid.
        # If empty, it is a method call without any actions.
        actions_map: MappingProxyType[TokenUid, tuple[NCAction, ...]]
        if not actions:
            actions_map = _EMPTY_MAP
        else:
            from hathor.verification.nano_header_verifier import NanoHeaderVerifier
            try:
                NanoHeaderVerifier.verify_action_list(actions)
            except TxValidationError as e:
                raise NCInvalidContext('invalid nano context') from e

            actions_map = cls.__group_actions__(actions)

        vertex_data = VertexData.create_from_vertex(vertex)
        vertex_meta = vertex.get_metadata()

        block_data: BlockData | None = None
        if vertex_meta.first_block is not None:
            # The context is also created when getting the tx's `to_json` for example,
            # and in this case it might not be confirmed yet.
            assert vertex.storage is not None
            block = vertex.storage.get_block(vertex_meta.first_block)
            block_data = BlockData.create_from_block(block)

        return Context(
            caller_id=caller_id,
            vertex_data=vertex_data,
            block_data=block_data,
            actions=actions_map,
        )

    def __init__(
        self,
        *,
        caller_id: CallerId,
        vertex_data: VertexData,
        block_data: BlockData | None,
        actions: MappingProxyType[TokenUid, tuple[NCAction, ...]],
    ) -> None:
        # Dict of action where the key is the token_uid.
        # If empty, it is a method call without any actions.
        self.__actions = actions

        self.__all_actions__: tuple[NCAction, ...] = tuple(chain(*self.__actions.values()))

        # Vertex calling the method.
        self.__vertex = vertex_data

        # Block executing the vertex.
        self.__block = block_data

        # Address calling the method.
        self.__caller_id = caller_id

    @property
    def vertex(self) -> VertexData:
        return self.__vertex

    @property
    def block(self) -> BlockData:
        assert self.__block is not None
        return self.__block

    @property
    def caller_id(self) -> CallerId:
        """Get the caller ID which can be either an Address or a ContractId."""
        return self.__caller_id

    def get_caller_address(self) -> Address | None:
        """Get the caller address if the caller is an address, None if it's a contract."""
        match self.caller_id:
            case Address():
                return self.caller_id
            case ContractId():
                return None
            case _:  # pragma: no cover
                assert_never(self.caller_id)

    def get_caller_contract_id(self) -> ContractId | None:
        """Get the caller contract ID if the caller is a contract, None if it's an address."""
        match self.caller_id:
            case Address():
                return None
            case ContractId():
                return self.caller_id
            case _:  # pragma: no cover
                assert_never(self.caller_id)

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
            caller_id=self.caller_id,
            vertex_data=self.vertex,
            block_data=self.block,  # We only copy during execution, so we know the block must not be `None`.
            actions=self.actions,
        )

    def to_json(self) -> dict[str, Any]:
        """Return a JSON representation of the context."""
        caller_id: str
        match self.caller_id:
            case Address():
                caller_id = get_address_b58_from_bytes(self.caller_id)
            case ContractId():
                caller_id = self.caller_id.hex()
            case _:  # pragma: no cover
                assert_never(self.caller_id)

        return {
            'actions': [action.to_json() for action in self.__all_actions__],
            'caller_id': caller_id,
            'timestamp': self.__block.timestamp if self.__block is not None else None,
            # XXX: Deprecated attribute
            'address': caller_id,
        }
