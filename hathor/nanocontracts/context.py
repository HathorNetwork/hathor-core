# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Sequence

from hathor.nanocontracts.types import CallerId, NCAction, TokenUid
from hathor.nanocontracts.vertex_data import create_block_data_from_block, create_vertex_data_from_vertex

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
