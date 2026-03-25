# Copyright 2026 Hathor Labs
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

from typing_extensions import deprecated

from hathor.crypto.util import get_address_b58_from_bytes
from hathor.nanocontracts.exception import NCFail, NCInvalidContext
from hathor.nanocontracts.types import Address, CallerId, ContractId, NCAction, TokenUid
from hathor.nanocontracts.vertex_data import BlockData, VertexData
from hathor.transaction.exceptions import TxValidationError
from hathorlib.nanocontracts.versions import BlueprintVersion

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
    __slots__ = (
        '__raw_blueprint_version',
        '__caller_id',
        '__vertex',
        '__block',
        '__actions_by_token__',
        '__all_actions__',
    )
    __caller_id: CallerId
    __vertex: VertexData
    __block: BlockData | None
    __actions_by_token__: MappingProxyType[TokenUid, tuple[NCAction, ...]]

    @staticmethod
    def __group_actions__(actions: Sequence[NCAction]) -> MappingProxyType[TokenUid, tuple[NCAction, ...]]:
        actions_map: defaultdict[TokenUid, tuple[NCAction, ...]] = defaultdict(tuple)
        for action in actions:
            actions_map[action.token_uid] = (*actions_map[action.token_uid], action)
        return MappingProxyType(actions_map)

    def __init__(
        self,
        *,
        caller_id: CallerId,
        vertex_data: VertexData,
        block_data: BlockData | None,
        actions: MappingProxyType[TokenUid, tuple[NCAction, ...]],
        blueprint_version: BlueprintVersion | None = None
    ) -> None:
        # Nullable BlueprintVersion. It must be set before nano execution, by the Runner.
        self.__raw_blueprint_version = blueprint_version

        # Dict of action where the key is the token_uid.
        # If empty, it is a method call without any actions.
        self.__actions_by_token__ = actions

        self.__all_actions__: tuple[NCAction, ...] = tuple(chain(*self.__actions_by_token__.values()))

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

    @property
    def __blueprint_version(self) -> BlueprintVersion:
        """
        Non-nullable version of `__raw_blueprint_version`, to be used internally.
        Not to be confused with the `blueprint_version` property, which is user-facing.
        """
        assert self.__raw_blueprint_version is not None
        return self.__raw_blueprint_version

    @property
    def blueprint_version(self) -> BlueprintVersion:
        """Get the Blueprint version."""
        match self.__blueprint_version:
            case BlueprintVersion.V1:
                raise NCFail('`Context.blueprint_version` is not supported yet.')
            case BlueprintVersion.V2:
                return self.__blueprint_version
            case _:
                assert_never(self.__blueprint_version)

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
    @deprecated('Use `Context.actions_by_token` instead')
    def actions(self) -> MappingProxyType[TokenUid, tuple[NCAction, ...]]:
        """Get a mapping of actions per token. Deprecated in BlueprintVersion.V2"""
        match self.__blueprint_version:
            case BlueprintVersion.V1:
                return self.__actions_by_token__
            case BlueprintVersion.V2:
                raise NCFail('`Context.actions` has been deprecated. Use `Context.actions_by_token` instead.')
            case _:
                assert_never(self.__blueprint_version)

    @property
    @deprecated('Use `Context.all_actions` instead')
    def actions_list(self) -> Sequence[NCAction]:
        """Get a list of all actions. Deprecated in BlueprintVersion.V2"""
        match self.__blueprint_version:
            case BlueprintVersion.V1:
                return tuple(self.__all_actions__)
            case BlueprintVersion.V2:
                raise NCFail('`Context.actions_list` has been deprecated. Use `Context.all_actions` instead.')
            case _:
                assert_never(self.__blueprint_version)

    @property
    def all_actions(self) -> Sequence[NCAction]:
        """Get a sequence of all actions."""
        match self.__blueprint_version:
            case BlueprintVersion.V1:
                raise NCFail('`Context.all_actions` is not supported yet.')
            case BlueprintVersion.V2:
                return tuple(self.__all_actions__)
            case _:
                assert_never(self.__blueprint_version)

    @property
    def actions_by_token(self) -> MappingProxyType[TokenUid, tuple[NCAction, ...]]:
        """Get a mapping of actions per token."""
        match self.__blueprint_version:
            case BlueprintVersion.V1:
                raise NCFail('`Context.actions_by_token` is not supported yet.')
            case BlueprintVersion.V2:
                return self.__actions_by_token__
            case _:
                assert_never(self.__blueprint_version)

    def get_single_action(self, token_uid: TokenUid) -> NCAction:
        """
        Utility method to get the single action for the provided token,
        and that is the only action in the whole Context.

        - If there are no actions, this method will fail.
        - If there are any other actions for the provided token, this method will fail.
        - If there are any other actions for any other tokens, this method will fail.
        """
        match self.__blueprint_version:
            case BlueprintVersion.V1:
                return self.__legacy_get_single_action(token_uid)
            case BlueprintVersion.V2:
                if len(self.all_actions) != 1:
                    raise NCFail(f'expected exactly 1 action in the whole Context, for token {token_uid.hex()}')
                return self.__legacy_get_single_action(token_uid)
            case _:
                assert_never(self.__blueprint_version)

    def get_token_single_action(self, token_uid: TokenUid) -> NCAction:
        """
        Utility method to get the single action for the provided token,
        and there may be other actions for other tokens.

        - If there are no actions, this method will fail.
        - If there are any other actions for the provided token, this method will fail.
        - If there are any other actions for any other tokens, this method will succeed.
        """
        match self.__blueprint_version:
            case BlueprintVersion.V1:
                raise NCFail('`Context.get_token_single_action` is not supported yet.')
            case BlueprintVersion.V2:
                return self.__legacy_get_single_action(token_uid)
            case _:
                assert_never(self.__blueprint_version)

    def __legacy_get_single_action(self, token_uid: TokenUid) -> NCAction:
        token_actions = self.__actions_by_token__.get(token_uid)
        if token_actions is None or len(token_actions) != 1:
            raise NCFail(f'expected exactly 1 action for token {token_uid.hex()}')
        return token_actions[0]

    def __prepare_for_new_runner_call__(self, blueprint_version: BlueprintVersion) -> Context:
        """Return a copy of the context."""
        ctx = Context(
            caller_id=self.caller_id,
            vertex_data=self.vertex,
            block_data=self.block,  # We only copy during execution, so we know the block must not be `None`.
            actions=self.__actions_by_token__,
        )
        ctx.__raw_blueprint_version = blueprint_version
        return ctx

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
