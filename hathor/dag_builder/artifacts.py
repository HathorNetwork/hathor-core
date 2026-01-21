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

from typing import TYPE_CHECKING, Callable, Iterator, NamedTuple, Sequence, TypeVar

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
        self._last_propagated: str | None = None
        self._step_fns: list[Callable[[DAGNode, BaseTransaction], None]] = []

    def register_step_fn(self, step_fn: Callable[[DAGNode, BaseTransaction], None]) -> None:
        """Register a new step function to be called between vertex propagations."""
        self._step_fns.append(step_fn)

    def get_typed_vertex(self, name: str, type_: type[T]) -> T:
        """Get a vertex by name, asserting it is of the provided type."""
        _, vertex = self.by_name[name]
        assert isinstance(vertex, type_)
        return vertex

    def get_typed_vertices(self, names: Sequence[str], type_: type[T]) -> Sequence[T]:
        """Get a list of vertices by name, asserting they are of the provided type."""
        return tuple(self.get_typed_vertex(name, type_) for name in names)

    def propagate_with(
        self,
        manager: HathorManager,
        *,
        up_to: str | None = None,
        up_to_before: str | None = None,
    ) -> None:
        """
        Propagate vertices using the provided manager up to the provided node name, included.  Last propagation is
        preserved in memory so you can make a sequence of propagate_with().

        Use `up_to` to stop propagation after the specified node has been propagated. Alternatively, use `up_to_before`
        to stop right before propagating the specified node.

        Propagations are performed using `VertexHandler._old_on_new_vertex()`, which bypasses mempool rules by default.
        Set `new_relayed_vertex` to True to apply these rules during propagation.
        """
        found_begin = self._last_propagated is None
        found_end = False

        for node, vertex in self.list:
            if up_to_before and node.name == up_to_before:
                found_end = True
                break

            if found_begin:
                try:
                    assert manager.vertex_handler.on_new_relayed_vertex(vertex)
                except Exception as e:
                    raise Exception(f'failed on_new_tx({node.name})') from e
                for step_fn in self._step_fns:
                    step_fn(node, vertex)
                self._last_propagated = node.name

            if node.name == self._last_propagated:
                found_begin = True

            if up_to and node.name == up_to:
                found_end = True
                break

        assert found_begin, f'node "{self._last_propagated}" not found'
        assert up_to is None or found_end, f'node "{up_to}" not found'
