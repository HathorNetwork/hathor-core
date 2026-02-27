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
from collections import defaultdict
from types import ModuleType
from typing import Iterator

from structlog import get_logger
from typing_extensions import Self

from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.dag_builder.artifacts import DAGArtifacts
from hathor.dag_builder.tokenizer import Token, TokenType
from hathor.dag_builder.types import (
    AttributeType,
    DAGInput,
    DAGNode,
    DAGNodeType,
    DAGOutput,
    VertexResolverType,
    WalletFactoryType,
)
from hathor.dag_builder.utils import is_literal, parse_amount_token
from hathor.manager import HathorManager
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.util import initialize_hd_wallet
from hathor.wallet import BaseWallet

logger = get_logger()

NC_DEPOSIT_KEY = 'nc_deposit'
NC_WITHDRAWAL_KEY = 'nc_withdrawal'
TOKEN_VERSION_KEY = 'token_version'
FEE_KEY = 'fee'
NC_TRANSFER_INPUT_KEY = 'nc_transfer_input'
NC_TRANSFER_OUTPUT_KEY = 'nc_transfer_output'


class DAGBuilder:
    def __init__(
        self,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
        genesis_wallet: BaseWallet,
        wallet_factory: WalletFactoryType,
        vertex_resolver: VertexResolverType,
        nc_catalog: NCBlueprintCatalog,
        blueprints_module: ModuleType | None = None,
    ) -> None:
        from hathor.dag_builder.default_filler import DefaultFiller
        from hathor.dag_builder.tokenizer import tokenize
        from hathor.dag_builder.vertex_exporter import VertexExporter

        self.log = logger.new()

        self._nodes: dict[str, DAGNode] = {}
        self._tokenize = tokenize
        self._filler = DefaultFiller(self, settings, daa)
        self._exporter = VertexExporter(
            builder=self,
            settings=settings,
            daa=daa,
            genesis_wallet=genesis_wallet,
            wallet_factory=wallet_factory,
            vertex_resolver=vertex_resolver,
            nc_catalog=nc_catalog,
            blueprints_module=blueprints_module,
        )

    @staticmethod
    def from_manager(
        manager: HathorManager,
        genesis_words: str,
        wallet_factory: WalletFactoryType,
        blueprints_module: ModuleType | None = None
    ) -> DAGBuilder:
        """Create a DAGBuilder instance from a HathorManager instance."""
        assert manager.tx_storage.nc_catalog
        return DAGBuilder(
            settings=manager._settings,
            daa=manager.daa,
            genesis_wallet=initialize_hd_wallet(genesis_words),
            wallet_factory=wallet_factory,
            vertex_resolver=lambda x: manager.cpu_mining_service.resolve(x),
            nc_catalog=manager.tx_storage.nc_catalog,
            blueprints_module=blueprints_module,
        )

    def get_main_wallet(self) -> BaseWallet:
        return self._exporter.get_wallet('main')

    def parse_tokens(self, tokens: Iterator[Token]) -> None:
        """Parse tokens and update the DAG accordingly."""
        for parts in tokens:
            match parts:
                case (TokenType.PARENT, (_from, _to)):
                    self.add_parent_edge(_from, _to)

                case (TokenType.SPEND, (_from, _to, _txout_index)):
                    self.add_spending_edge(_from, _to, _txout_index)

                case (TokenType.ATTRIBUTE, (name, key, value)):
                    self.add_attribute(name, key, value)

                case (TokenType.ORDER_BEFORE, (_from, _to)):
                    self.add_deps(_from, _to)

                case (TokenType.OUTPUT, (name, index, amount, token, attrs)):
                    self.set_output(name, index, amount, token, attrs)

                case (TokenType.BLOCKCHAIN, (name, first_parent, begin_index, end_index)):
                    self.add_blockchain(name, first_parent, begin_index, end_index)

                case _:
                    raise NotImplementedError(parts)

    def _get_node(self, name: str) -> DAGNode:
        """Return a node."""
        return self._nodes[name]

    def _get_or_create_node(self, name: str, *, default_type: DAGNodeType = DAGNodeType.Unknown) -> DAGNode:
        """Return a node, creating one if needed."""
        if name not in self._nodes:
            node = DAGNode(name=name, type=default_type)
            self._nodes[name] = node
        else:
            node = self._nodes[name]
            if node.type == DAGNodeType.Unknown:
                node.type = default_type
            else:
                if default_type != DAGNodeType.Unknown:
                    assert node.type is default_type, f'{node.type} != {default_type}'
        return node

    def add_deps(self, _from: str, _to: str) -> Self:
        """Add a dependency between two nodes. For clarity, `_to` has to be created before `_from`."""
        from_node = self._get_or_create_node(_from)
        self._get_or_create_node(_to)
        from_node.deps.add(_to)
        return self

    def update_balance(self, name: str, token: str, value: int) -> Self:
        """Update the expected balance for a given token, where balance = sum(outputs) - sum(inputs).

        =0 means sum(txouts) = sum(txins)
        >0 means sum(txouts) > sum(txins), e.g., withdrawal
        <0 means sum(txouts) < sum(txins), e.g., deposit
        """
        node = self._get_or_create_node(name)
        node.balances[token] = node.balances.get(token, 0) + value
        if token != 'HTR':
            self._get_or_create_node(token, default_type=DAGNodeType.Token)
            self.add_deps(name, token)
        return self

    def add_blockchain(self, prefix: str, first_parent: str | None, first_index: int, last_index: int) -> Self:
        """Add a sequence of nodes representing a chain of blocks."""
        prev = first_parent
        for i in range(first_index, last_index + 1):
            name = f'{prefix}{i}'
            self._get_or_create_node(name, default_type=DAGNodeType.Block)
            if prev is not None:
                self.add_parent_edge(name, prev)
            prev = name
        return self

    def add_parent_edge(self, _from: str, _to: str) -> Self:
        """Add a parent edge between two nodes. For clarity, `_to` has to be created before `_from`."""
        self._get_or_create_node(_to)
        from_node = self._get_or_create_node(_from)
        from_node.parents.add(_to)
        return self

    def add_spending_edge(self, _from: str, _to: str, _txout_index: int) -> Self:
        """Add a spending edge between two nodes. For clarity, `_to` has to be created before `_from`."""
        to_node = self._get_or_create_node(_to)
        if len(to_node.outputs) <= _txout_index:
            to_node.outputs.extend([None] * (_txout_index - len(to_node.outputs) + 1))
            to_node.outputs[_txout_index] = DAGOutput(0, '', {})
        from_node = self._get_or_create_node(_from)
        from_node.inputs.add(DAGInput(_to, _txout_index))
        return self

    def set_output(self, name: str, index: int, amount: int, token: str, attrs: AttributeType) -> Self:
        """Set information about an output."""
        node = self._get_or_create_node(name)
        if len(node.outputs) <= index:
            node.outputs.extend([None] * (index - len(node.outputs) + 1))
        node.outputs[index] = DAGOutput(amount, token, attrs)
        if token != 'HTR':
            self._get_or_create_node(token, default_type=DAGNodeType.Token)
            node.deps.add(token)
        return self

    def _parse_expression(self, value: str) -> ast.AST:
        try:
            ret = ast.parse(value, mode='eval').body
        except SyntaxError as e:
            raise SyntaxError(f'failed parsing "{value}"') from e
        return ret

    def _add_nc_attribute(self, name: str, key: str, value: str) -> None:
        """Handle attributes related to nanocontract transactions."""
        node = self._get_or_create_node(name)
        if key == 'nc_id':
            parsed_value = self._parse_expression(value)
            if isinstance(parsed_value, ast.Name):
                node.deps.add(parsed_value.id)
            elif isinstance(parsed_value, ast.Call):
                for arg in parsed_value.args:
                    if isinstance(arg, ast.Name):
                        node.deps.add(arg.id)
                    elif isinstance(arg, ast.Attribute):
                        assert isinstance(arg.value, ast.Name)
                        node.deps.add(arg.value.id)
            node.attrs[key] = parsed_value

        elif key in (NC_DEPOSIT_KEY, NC_WITHDRAWAL_KEY):
            token, amount, args = parse_amount_token(value)
            if args:
                raise SyntaxError(f'unexpected args in `{value}`')
            if amount < 0:
                raise SyntaxError(f'unexpected negative action in `{value}`')
            multiplier = 1 if key == NC_WITHDRAWAL_KEY else -1
            self.update_balance(name, token, amount * multiplier)
            actions = node.get_attr_list(key, default=[])
            actions.append((token, amount))
            node.attrs[key] = actions

        elif key == NC_TRANSFER_INPUT_KEY:
            transfer_inputs = node.get_attr_list(key, default=[])
            token, amount, (wallet,) = parse_amount_token(value)
            if amount < 0:
                raise SyntaxError(f'unexpected negative amount in `{key}`')
            transfer_inputs.append((wallet, token, amount))
            node.attrs[key] = transfer_inputs

        elif key == NC_TRANSFER_OUTPUT_KEY:
            transfer_outputs = node.get_attr_list(key, default=[])
            token, amount, (wallet,) = parse_amount_token(value)
            if amount < 0:
                raise SyntaxError(f'unexpected negative amount in `{key}`')
            transfer_outputs.append((wallet, token, amount))
            node.attrs[key] = transfer_outputs

        else:
            node.attrs[key] = value

    def _add_ocb_attribute(self, name: str, key: str, value: str) -> None:
        """Handle attributes related to on-chain blueprint transactions."""
        node = self._get_or_create_node(name)
        node.type = DAGNodeType.OnChainBlueprint
        if key == 'ocb_code':
            node.attrs[key] = value

        elif key == 'ocb_private_key':
            if not is_literal(value):
                raise SyntaxError(f'ocb_private_key must be a bytes literal: {value}')
            node.attrs[key] = value

        elif key == 'ocb_password':
            if not is_literal(value):
                raise SyntaxError(f'ocb_password must be a bytes literal: {value}')
            node.attrs[key] = value

        else:
            node.attrs[key] = value

    def _append_fee(self, name: str, key: str, value: str) -> None:
        """Add a fee payment."""
        assert key == FEE_KEY
        node = self._get_or_create_node(name)
        fees = node.get_attr_list(key, default=[])
        token, amount, args = parse_amount_token(value)
        if args:
            raise SyntaxError(f'unexpected args in `{value}`')
        if amount < 0:
            raise SyntaxError(f'unexpected negative fee in `{value}`')
        self.update_balance(name, token, -amount)
        fees.append((token, amount))
        node.attrs[key] = fees

    def add_attribute(self, name: str, key: str, value: str) -> Self:
        """Add an attribute to a node."""
        if key.startswith('nc_'):
            self._add_nc_attribute(name, key, value)
            return self

        if key.startswith('ocb_'):
            self._add_ocb_attribute(name, key, value)
            return self

        if key == FEE_KEY:
            self._append_fee(name, key, value)
            return self

        if key.startswith('balance_'):
            node = self._get_or_create_node(name)
            token = key[len('balance_'):]
            if token in node.balances:
                raise SyntaxError(f'{name}: balance set more than once for {token}')
            self.update_balance(name, token, int(value))
            return self

        node = self._get_or_create_node(name)
        if key not in node.attrs:
            node.attrs[key] = value
        else:
            raise SyntaxError('attribute key duplicated')

        return self

    def topological_sorting(self) -> Iterator[DAGNode]:
        """Run a topological sort on the DAG, yielding nodes in an order that respects all dependency constraints."""
        direct_deps: dict[str, set[str]] = {}
        rev_deps: dict[str, set[str]] = defaultdict(set)
        seen: set[str] = set()
        candidates: list[str] = []
        for name, node in self._nodes.items():
            assert name == node.name
            deps = set(node.get_all_dependencies())
            assert name not in direct_deps
            direct_deps[name] = deps
            for x in deps:
                rev_deps[x].add(name)
            if len(deps) == 0:
                candidates.append(name)

        for _ in range(len(self._nodes)):
            if len(candidates) == 0:
                self.log.error(
                    'fail because there is at least one cycle in the dependencies',
                    direct_deps=direct_deps,
                    rev_deps=rev_deps,
                    seen=seen,
                    not_seen=set(self._nodes.keys()) - seen,
                    nodes=self._nodes,
                )
                raise RuntimeError('there is at least one cycle')
            name = candidates.pop()
            assert name not in seen
            seen.add(name)
            for d in rev_deps[name]:
                direct_deps[d].remove(name)
                if len(direct_deps[d]) == 0:
                    candidates.append(d)
                    del direct_deps[d]
            node = self._get_node(name)
            yield node

    def build(self) -> DAGArtifacts:
        """Build all the transactions based on the DAG."""
        self._filler.run()
        return DAGArtifacts(self._exporter.export())

    def build_from_str(self, content: str) -> DAGArtifacts:
        """Run build() after creating an initial DAG from a string."""
        self.parse_tokens(self._tokenize(content))
        return self.build()
