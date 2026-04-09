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
from typing import TYPE_CHECKING, Sequence

from hathor.nanocontracts.exception import NCInvalidContext
from hathor.nanocontracts.types import CallerId, NCAction, TokenUid
from hathor.nanocontracts.vertex_data import create_block_data_from_block, create_vertex_data_from_vertex
from hathor.transaction.exceptions import TxValidationError
# Re-export from hathorlib for backward compatibility
from hathorlib.nanocontracts.context import *  # noqa: F401,F403
from hathorlib.nanocontracts.context import Context  # noqa: F401
from hathorlib.nanocontracts.vertex_data import BlockData

if TYPE_CHECKING:
    from hathor.transaction import Vertex

_EMPTY_MAP: MappingProxyType[TokenUid, tuple[NCAction, ...]] = MappingProxyType({})


def create_context_from_vertex(
    *,
    caller_id: CallerId,
    vertex: Vertex,
    actions: Sequence[NCAction],
) -> Context:
    """Create a Context from a transaction vertex. This is a hathor-specific factory function."""
    actions_map: MappingProxyType[TokenUid, tuple[NCAction, ...]]
    if not actions:
        actions_map = _EMPTY_MAP
    else:
        from hathor.verification.nano_header_verifier import NanoHeaderVerifier
        try:
            NanoHeaderVerifier.verify_action_list(actions)
        except TxValidationError as e:
            raise NCInvalidContext('invalid nano context') from e

        actions_map = Context.__group_actions__(actions)

    vertex_data = create_vertex_data_from_vertex(vertex)
    vertex_meta = vertex.get_metadata()

    block_data: BlockData | None = None
    if vertex_meta.first_block is not None:
        assert vertex.storage is not None
        block = vertex.storage.get_block(vertex_meta.first_block)
        block_data = create_block_data_from_block(block)

    return Context(
        caller_id=caller_id,
        vertex_data=vertex_data,
        block_data=block_data,
        actions=actions_map,
    )
