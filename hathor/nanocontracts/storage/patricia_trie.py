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

import hashlib
from dataclasses import dataclass, field
from itertools import chain
from typing import Iterable, NamedTuple, NewType, Optional

from hathor.nanocontracts.storage.backends import NodeTrieStore

NodeId = NewType('NodeId', bytes)


class DictChildren(dict[bytes, NodeId]):
    """Data structure to store children of tree nodes."""
    def find_prefix(self, a: bytes) -> Optional[tuple[bytes, NodeId]]:
        """Find the key that is a prefix of `a`."""
        # TODO Optimize search.
        for key, node_id in self.items():
            if a.startswith(key):
                return key, node_id
        return None

    def copy(self):
        """Return a copy of itself."""
        return DictChildren(self)


@dataclass(kw_only=True, slots=True)
class Node:
    """This is a node in the Patricia trie.

    Each node can carry an object or not. If a node does not carry an object, its key has never been directly added to
    the trie but it was created because some keys have the same prefix.

    Note: We might be able to remove the length.
    """

    key: bytes
    length: int
    content: Optional[bytes] = None
    children: DictChildren = field(default_factory=DictChildren)
    _id: Optional[NodeId] = None

    @property
    def id(self) -> NodeId:
        assert self._id is not None
        return self._id

    def copy(self, content: Optional[bytes] = None, children: Optional[DictChildren] = None) -> 'Node':
        """Generate a copy of this node except by the id field."""
        content = content if content is not None else self.content
        children = children if children is not None else self.children.copy()
        return Node(key=self.key, length=self.length, content=content, children=children)

    def calculate_id(self) -> NodeId:
        """Calculate a merkle hash to serve as node id.

        This method assumes that all children already have their ids calculated.
        """
        h = hashlib.sha256()
        h.update(self.key)
        if self.content is not None:
            h.update(self.content)
        sorted_child_ids = sorted(list(self.children.values()))
        for child_id in sorted_child_ids:
            h.update(child_id)
        return NodeId(h.digest())

    def update_id(self) -> None:
        """Update node id."""
        assert self._id is None
        self._id = self.calculate_id()


class IterDFSNode(NamedTuple):
    """Item yielded by `PatriciaTrie.iter_dfs()`."""
    node: Node
    height: int
    is_leaf: bool


class PatriciaTrie:
    """This object manages one or more Patricia tries; each Patricia trie is a compressed radix trie.

    All nodes are immutable. So every update will create a new path of nodes from leaves to a new root.

    - The tree structure must be the same regardless of the order the items are added.
    """

    __slots__ = ('_local_changes', '_db', 'root')

    def __init__(self, store: NodeTrieStore, *, root_id: Optional[NodeId] = None) -> None:
        self._local_changes: dict[NodeId, Node] = {}
        self._db = store
        if root_id is None:
            self.root: Node = Node(key=b'', length=0)
            self.root.update_id()
            self._db[self.root.id] = self.root
        else:
            self.root = self._db[root_id]
            assert self.root.id == root_id

    def get_store(self) -> NodeTrieStore:
        return self._db

    def commit(self) -> None:
        """Flush all local changes from self.root to the database. All other nodes not accessed from self.root
        will be discarded.

        This method should be called after all changes have been made to reduce the total number of nodes.
        """
        self._commit_dfs(self.root)
        self._local_changes = {}

    def _commit_dfs(self, node: Node) -> None:
        """Auxiliary method to run a dfs from self.root and flush local changes to the database."""
        self._add_to_db_or_assert(node)
        for child_id in node.children.values():
            child = self._local_changes.get(child_id, None)
            if child is not None:
                self._commit_dfs(child)
            else:
                assert child_id in self._db

    def _add_to_db_or_assert(self, node: Node) -> None:
        """Auxiliary method to either add to the database or check consistency."""
        if node.id in self._db:
            assert self._db[node.id] == node
        else:
            self._db[node.id] = node

    def rollback(self) -> None:
        """Discard all local changes."""
        self._local_changes = {}

    def is_dirty(self) -> bool:
        """Check if there is any pending local change."""
        return bool(self._local_changes)

    def get_node(self, node_id: NodeId) -> Node:
        """Return a node from local changes or the database."""
        if node_id in self._local_changes:
            return self._local_changes[node_id]
        return self._db[node_id]

    def iter_dfs(self, *, node: Optional[Node] = None) -> Iterable[IterDFSNode]:
        """Iterate from a node in a depth-first search."""
        if node is None:
            node = self.root
        assert node is not None
        yield from self._iter_dfs(node=node, depth=0)

    def _iter_dfs(self, *, node: Node, depth: int) -> Iterable[IterDFSNode]:
        """Iterate from a node in a depth-first search."""
        is_leaf = bool(not node.children)
        yield IterDFSNode(node, depth, is_leaf)
        for _, child_id in node.children.items():
            child = self.get_node(child_id)
            yield from self._iter_dfs(node=child, depth=depth + 1)

    def _find_nearest_node(self,
                           key: bytes,
                           *,
                           root_id: Optional[NodeId] = None,
                           log_path: Optional[list[tuple[bytes, Node]]] = None) -> Node:
        """Find the nearest node in the trie starting from root_id.

        Notice that it does not have to be a match. The nearest node will share the longest common
        prefix with the provided key.
        """

        node: Node
        if root_id is None:
            node = self.root
        else:
            node = self.get_node(root_id)

        last_match: bytes = b''

        while True:
            if log_path is not None:
                log_path.append((last_match, node))

            if node.key == key:
                return node

            suffix = key[node.length:]
            match = node.children.find_prefix(suffix)
            if match is not None:
                last_match, next_node_id = match
            else:
                return node

            node = self.get_node(next_node_id)

    @staticmethod
    def _find_longest_common_prefix(a: bytes, b: bytes) -> int:
        """Return the index of the longest common prefix between `a` and `b`.

        If a and b does not share any prefix, returns -1.
        Otherwise, return an integer in the range [0, min(|a|, |b|) - 1].
        """
        n = min(len(a), len(b))
        for i in range(n):
            if a[i] != b[i]:
                return i - 1
        return n - 1

    def print_dfs(self, node: Optional[Node] = None, *, depth: int = 0) -> None:
        if node is None:
            node = self.root

        prefix = '    ' * depth
        print(f'{prefix}key: {node.key!r}')
        print(f'{prefix}length: {node.length}')
        print(f'{prefix}content: {node.content!r}')
        print(f'{prefix}n_children: {len(node.children)}')
        print(f'{prefix}id: {node.id.hex()}')
        print()
        for k, child_id in node.children.items():
            print(f'    {prefix}--- {k!r} ---')
            child = self.get_node(child_id)
            self.print_dfs(child, depth=depth + 1)

    def _build_path(self, log_path: list[tuple[bytes, Node]], new_nodes: list[tuple[bytes, Node]]) -> None:
        """Build a new path of nodes from the new nodes being added and the current nodes at the trie."""
        prev_suffix: bytes | None = None

        prev_suffix, _ = new_nodes[0]
        log_path_copy: list[tuple[bytes, Node]] = []
        for suffix, node in log_path[::-1]:
            new_node = node.copy()
            assert prev_suffix is not None
            del new_node.children[prev_suffix]
            log_path_copy.append((suffix, new_node))
            prev_suffix = suffix

        prev: Node | None = None
        prev_suffix = None
        for suffix, node in chain(new_nodes[::-1], log_path_copy):
            if prev is not None:
                assert prev.id is not None
                assert prev_suffix is not None
                node.children[prev_suffix] = prev.id
            node.update_id()
            self._local_changes[node.id] = node
            prev = node
            prev_suffix = suffix

        assert prev is not None
        self.root = prev

    def _encode_key(self, key: bytes) -> bytes:
        """Encode key for internal use.

        This encoding mechanism is utilized to limit the maximum number of children a node can have."""
        return key.hex().encode('ascii')

    @staticmethod
    def _decode_key(key: bytes) -> bytes:
        """Decode key from internal format to the provided one.

        During the trie operation, keys are split and they might not be a valid hex string.
        In this cases, we append a '0' at the end.
        """
        if len(key) % 2 == 1:
            key += b'0'
        return bytes.fromhex(key.decode('ascii'))

    def _update(self, key: bytes, content: bytes) -> None:
        """Internal method to update a key.

        This method never updates a node. It actually copies the node and creates a new path
        from that node to the root.
        """
        # The new_nodes carries the nodes that currently do not exist in the store.
        # These nodes still do not have an id. Their ids will be calculated in the _build_path() method.
        new_nodes: list[tuple[bytes, Node]] = []

        # The log_path is used to backtrack the nearest node to the root. These nodes will be copied in
        # the _build_path() method.
        log_path: list[tuple[bytes, Node]] = []

        # First, search for the nearest node to `key`. It either matches the key or is a prefix of the key.
        parent = self._find_nearest_node(key, log_path=log_path)
        # The last item in the log_path is equal to the returned node. We discard it because the parent
        # will be added to the `new_nodes` later.
        parent_match, _ = log_path.pop()

        if parent.key == key:
            # If the nearest node stores `key`, then we will just copy it and build a new path up to the root.
            new_nodes.append((parent_match, parent.copy(content=content)))
            self._build_path(log_path, new_nodes)
            return

        # If this point is reached, then `parent.key` is a prefix of `key`. So we have to check whether
        # any of parent's children shares a prefix with `key` too. Notice that at most one children can
        # share a prefix with `key`.
        # TODO Optimize this search.
        suffix = key[parent.length:]
        for k, _v in parent.children.items():
            idx = self._find_longest_common_prefix(suffix, k)
            if idx < 0:
                # No share with `key`. So skip it.
                continue

            # Found the child the shares a prefix with `key`. So we can stop the search.
            # Now we have to add a "split node" between the parent and its child.
            #
            # Before: parent -> child
            # After:  parent -> split -> child
            common_key = key[:parent.length + idx + 1]
            common_key_suffix = suffix[:idx + 1]

            split = Node(
                key=common_key,
                length=len(common_key),
            )
            split.children[k[idx + 1:]] = _v

            parent_children_copy = parent.children.copy()
            del parent_children_copy[k]
            new_nodes.append((parent_match, parent.copy(children=parent_children_copy)))

            # Either the split node's key equals to `key` or not.
            if split.key == key:
                # If they are equal, the split node will store the object and we are done.
                split.content = content
                new_nodes.append((common_key_suffix, split))
                self._build_path(log_path, new_nodes)
                return

            # Otherwise, the split node will be the parent of the new node that will be created
            # to store the object.
            parent = split
            parent_match = common_key_suffix
            break

        # Finally, create the new node that will store the object.
        assert parent.key != key
        suffix = key[parent.length:]
        child = Node(
            key=key,
            length=len(key),
            content=content,
        )
        new_nodes.append((parent_match, parent.copy()))
        new_nodes.append((suffix, child))
        self._build_path(log_path, new_nodes)

    def _get(self, key: bytes, *, root_id: Optional[NodeId] = None) -> bytes:
        """Internal method to get the object-bytes of a key."""
        if key == b'':
            raise KeyError('key cannot be empty')
        node = self._find_nearest_node(key, root_id=root_id)
        if node.key != key:
            raise KeyError
        if node.content is None:
            raise KeyError
        return node.content

    def update(self, key: bytes, content: bytes) -> None:
        """Update the object of a key. This method might change the root of the trie."""
        real_key = self._encode_key(key)
        return self._update(real_key, content)

    def get(self, key: bytes, *, root_id: Optional[NodeId] = None) -> bytes:
        """Return the object of a key."""
        real_key = self._encode_key(key)
        return self._get(real_key, root_id=root_id)

    def has_key(self, key: bytes, *, root_id: Optional[NodeId] = None) -> bool:
        """Return true if the key exists."""
        try:
            self.get(key, root_id=root_id)
        except KeyError:
            return False
        return True
