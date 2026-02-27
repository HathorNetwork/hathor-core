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

import ast
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator, NamedTuple, TypeAlias

from sortedcontainers import SortedSet

from hathor.dag_builder.utils import get_literal
from hathor.transaction import BaseTransaction
from hathor.transaction.token_info import TokenVersion
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
    OnChainBlueprint = 'on_chain_blueprint'


@dataclass
class DAGNode:
    name: str
    type: DAGNodeType

    attrs: dict[str, Any] = field(default_factory=dict)
    inputs: set[DAGInput] = field(default_factory=set)
    outputs: list[DAGOutput | None] = field(default_factory=list)
    parents: SortedSet[str] = field(default_factory=SortedSet)
    deps: set[str] = field(default_factory=set)

    # expected balance of inputs and outputs per token
    #   =0 means sum(txouts) = sum(txins)
    #   >0 means sum(txouts) > sum(txins), e.g., withdrawal
    #   <0 means sum(txouts) < sum(txins), e.g., deposit
    balances: dict[str, int] = field(default_factory=dict)

    def get_all_dependencies(self) -> Iterator[str]:
        yield from self.parents
        yield from (name for name, _ in self.inputs)
        yield from self.deps

    def get_attr_ast(self, attr: str) -> Any:
        value = self.attrs.get(attr)
        assert isinstance(value, ast.AST)
        return value

    def get_attr_str(self, attr: str, *, default: str | None = None) -> str:
        """Return the value of an attribute, a default, or raise a SyntaxError if it doesn't exist."""
        if value := self.attrs.get(attr):
            assert isinstance(value, str)
            return value
        if default is not None:
            return default
        raise SyntaxError(f'missing required attribute: {self.name}.{attr}')

    def get_attr_list(self, attr: str, *, default: list[Any] | None = None) -> list[Any]:
        """Return the value of an attribute, a default, or raise a SyntaxError if it doesn't exist."""
        if value := self.attrs.get(attr):
            assert isinstance(value, list)
            return value
        if default is not None:
            return default
        raise SyntaxError(f'missing required attribute: {self.name}.{attr}')

    def get_attr_token_version(self) -> TokenVersion:
        """Return the token version for this node."""
        from hathor.dag_builder.builder import TOKEN_VERSION_KEY
        return TokenVersion[self.attrs.get(TOKEN_VERSION_KEY, TokenVersion.DEPOSIT.name).upper()]

    def get_required_literal(self, attr: str) -> str:
        """Return the value of a required attribute as a literal or raise a SyntaxError if it doesn't exist."""
        value = self.get_attr_str(attr)
        assert isinstance(value, str)
        return get_literal(value)


class DAGInput(NamedTuple):
    node_name: str
    txout_index: int


class DAGOutput(NamedTuple):
    amount: int
    token: str
    attrs: AttributeType
