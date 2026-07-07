# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING

from typing_extensions import override

from hathorlib.nanocontracts.nc_types import (
    BytesLikeNCType,
    BytesNCType,
    DictNCType,
    NCType,
    OptionalNCType,
    VarUint32NCType,
)
from hathorlib.serialization import Deserializer, Serializer

if TYPE_CHECKING:
    from hathorlib.nanocontracts.storage.patricia_trie import Node, NodeId


class NodeNCType(NCType['Node']):
    """ Used internally to (de)serialize a Node into/from the database.
    """

    __slots__ = ('_key', '_length', '_content', '_children', '_id')
    _key: NCType[bytes]
    _length: NCType[int]
    _content: NCType[bytes | None]
    _children: NCType[dict[bytes, NodeId]]
    # XXX: id is not optional, we're indicating that only nodes with id can be stored
    _id: NCType[NodeId]

    def __init__(self) -> None:
        from hathorlib.nanocontracts.storage.patricia_trie import NodeId
        self._key = BytesNCType()
        self._length = VarUint32NCType()
        self._content = OptionalNCType(BytesNCType())
        # XXX: ignores because mypy can't figure out that BytesLikeNCType[NodeId] provides a NCType[NodeId]
        self._children = DictNCType(BytesNCType(), BytesLikeNCType(NodeId))  # type: ignore[assignment]
        self._id = BytesLikeNCType(NodeId)

    @override
    def _check_value(self, value: Node, /, *, deep: bool) -> None:
        from hathorlib.nanocontracts.storage.patricia_trie import Node
        if not isinstance(value, Node):
            raise TypeError('expected Node class')

    @override
    def _serialize(self, serializer: Serializer, node: Node, /) -> None:
        # XXX: the order is important, must be the same between de/serialization
        self._key.serialize(serializer, node.key)
        self._length.serialize(serializer, node.length)
        self._content.serialize(serializer, node.content)
        self._children.serialize(serializer, node.children)
        self._id.serialize(serializer, node.id)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> Node:
        from hathorlib.nanocontracts.storage.patricia_trie import DictChildren, Node

        # XXX: the order is important, must be the same between de/serialization
        key = self._key.deserialize(deserializer)
        length = self._length.deserialize(deserializer)
        content = self._content.deserialize(deserializer)
        children = DictChildren(self._children.deserialize(deserializer))
        id_ = self._id.deserialize(deserializer)
        return Node(key=key, length=length, content=content, children=children, _id=id_)
