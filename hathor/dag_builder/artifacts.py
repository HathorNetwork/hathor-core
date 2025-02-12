# Copyright 2024 Hathor Labs
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

from typing import TYPE_CHECKING, Iterator, NamedTuple, TypeVar

from hathor.dag_builder.types import DAGNode
from hathor.manager import HathorManager

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction

T = TypeVar('T', bound='BaseTransaction')


class _Pair(NamedTuple):
    node: DAGNode
    vertex: BaseTransaction


class DAGArtifacts:
    def __init__(self, items: Iterator[tuple[DAGNode, BaseTransaction]]) -> None:
        self.by_name: dict[str, _Pair] = {}

        v: list[_Pair] = []
        for node, vertex in items:
            p = _Pair(node, vertex)
            v.append(p)
            self.by_name[node.name] = p

        self.list: tuple[_Pair, ...] = tuple(v)

    def get_typed_vertex(self, name: str, type_: type[T]) -> T:
        """Get a vertex by name, asserting it is of the provided type."""
        _, vertex = self.by_name[name]
        assert isinstance(vertex, type_)
        return vertex

    def get_typed_vertices(self, names: list[str], type_: type[T]) -> list[T]:
        """Get a list of vertices by name, asserting they are of the provided type."""
        return [self.get_typed_vertex(name, type_) for name in names]

    def propagate_with(self, manager: HathorManager) -> None:
        """Propagate vertices using the provided manager."""
        for _node, vertex in self.list:
            assert manager.on_new_tx(vertex, fails_silently=False)
