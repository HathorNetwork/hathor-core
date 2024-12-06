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

from typing import TYPE_CHECKING, Iterator, NamedTuple

from hathor.dag_builder.types import DAGNode

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction


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
