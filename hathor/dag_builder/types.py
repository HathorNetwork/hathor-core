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

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator, NamedTuple, TypeAlias

from hathor.transaction import BaseTransaction
from hathor.wallet import BaseWallet

AttributeType: TypeAlias = dict[str, str | int]
VertexResolverType: TypeAlias = Callable[[BaseTransaction], Any]
WalletFactoryType: TypeAlias = Callable[[], BaseWallet]


class DAGNodeType(Enum):
    Unknown = 'unknown'
    Block = 'block'
    Transaction = 'transaction'
    Token = 'token'
    Genesis = 'genesis'


@dataclass
class DAGNode:
    name: str
    type: DAGNodeType

    attrs: dict[str, str] = field(default_factory=dict)
    inputs: set[DAGInput] = field(default_factory=set)
    outputs: list[DAGOutput | None] = field(default_factory=list)
    parents: set[str] = field(default_factory=set)
    deps: set[str] = field(default_factory=set)

    def get_all_dependencies(self) -> Iterator[str]:
        yield from self.parents
        yield from (name for name, _ in self.inputs)
        yield from self.deps


class DAGInput(NamedTuple):
    node_name: str
    txout_index: int


class DAGOutput(NamedTuple):
    amount: int
    token: str
    attrs: AttributeType
