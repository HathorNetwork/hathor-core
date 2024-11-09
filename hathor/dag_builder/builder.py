from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterator, NamedTuple

from hathor.dag_builder.tokenizer import Token

class DAGBuilder:
    def __init__(self):
        self._nodes = {}

    def parse_tokens(self, tokens: Iterator) -> None:
        for parts in tokens:
            match parts:
                case (Token.PARENT, _from, _to):
                    self.add_parent_edge(_from, _to)

                case (Token.SPEND, _from, _to, _txout_index):
                    self.add_spending_edge(_from, _to, _txout_index)

                case (Token.ATTRIBUTE, name, key, value):
                    self.add_attribute(name, key, value)

                case (Token.ORDER_BEFORE, _from, _to):
                    self.add_deps(_from, _to)

                case (Token.OUTPUT, name, index, amount, token, attrs):
                    self.set_output(name, index, amount, token, attrs)

                case (Token.BLOCKCHAIN, name, first_parent, begin_index, end_index):
                    self.add_blockchain(name, first_parent, begin_index, end_index)

                case _:
                    raise NotImplementedError(parts)

    def _get_node(self, name, *, default_type='unknown'):
        if name not in self._nodes:
            self._nodes[name] = DAGNode(name=name, type=default_type)
        node = self._nodes[name]
        # TODO Set type if unknown.
        return node

    def add_deps(self, _from, _to):
        from_node = self._get_node(_from)
        self._get_node(_to)
        from_node.deps.add(_to)

    def add_blockchain(self, prefix: str, first_parent: str | None, first_index: int, last_index: int):
        prev = first_parent
        for i in range(first_index, last_index + 1):
            name = f'{prefix}{i}'
            self._get_node(name, default_type='block')
            if prev is not None:
                self.add_parent_edge(name, prev)
            prev = name

    def add_parent_edge(self, _from, _to):
        self._get_node(_to, default_type='transaction')
        from_node = self._get_node(_from, default_type='transaction')
        from_node.parents.add(_to)

    def add_spending_edge(self, _from, _to, _txout_index):
        self._get_node(_to, default_type='transaction')
        from_node = self._get_node(_from, default_type='transaction')
        from_node.inputs.add(DAGInput(_to, _txout_index))

    def set_output(self, name, index, amount, token, attrs):
        node = self._get_node(name)
        if len(node.outputs) <= index:
            node.outputs.extend([None] * (index - len(node.outputs) + 1))
        node.outputs[index] = DAGOutput(amount, token, attrs)
        if token != 'HTR':
            self._get_node(token, default_type='token')
            node.deps.add(token)

    def add_attribute(self, name, key, value):
        node = self._get_node(name)
        node.attrs[key] = value

    def topological_sorting(self) -> Iterator[DAGNode]:
        direct_deps: dict[str, str[str]] = {}
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
                # TODO improve error message showing at least one cycle
                print()
                print('direct_deps', direct_deps)
                print()
                print('rev_deps', rev_deps)
                print()
                print('seen', seen)
                print()
                print('not_seen', set(self._nodes.keys()) - seen)
                print()
                print('nodes')
                for node in self._nodes.values():
                    print(node)
                print()
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

    def build(self, tokenizer, settings, daa, genesis_wallet, wallet_factory) -> Iterator[tuple[str, 'BaseTransaction']]:
        from hathor.dag_builder.default_filler import DefaultFiller
        from hathor.dag_builder.vertex_exporter import VertexExporter

        filler = DefaultFiller(self, settings, daa)

        exporter = VertexExporter(self)
        exporter.set_genesis_wallet(genesis_wallet)
        exporter.set_wallet_factory(wallet_factory)
        exporter.set_daa(daa)
        exporter.set_settings(settings)

        self._get_node('dummy', default_type='transaction')

        self.parse_tokens(tokenizer)

        for node in self._nodes.values():
            if node.type == 'block':
                continue
            if node.type == 'genesis':
                continue
            if node.name == 'dummy':
                continue
            self.add_deps(node.name, 'dummy')

        filler.run()
        return exporter.export()


@dataclass(frozen=True)
class DAGNode:
    name: str
    type: str

    attrs: dict[str, str] = field(default_factory=dict)
    inputs: set[DAGInput] = field(default_factory=set)
    outputs: list[DAGOutput] = field(default_factory=list)
    parents: set[str] = field(default_factory=set)
    deps: set[str] = field(default_factory=set)

    def get_all_dependencies(self):
        yield from self.parents
        yield from (name for name, _ in self.inputs)
        yield from self.deps


class DAGInput(NamedTuple):
    node_name: str
    index: int


class DAGOutput(NamedTuple):
    amount: int
    token: str
    attrs: list[tuple[str, Any]]
