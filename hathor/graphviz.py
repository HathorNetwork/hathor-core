# Copyright 2021 Hathor Labs
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

from itertools import chain
from typing import Iterator

from graphviz import Digraph

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import BaseTransaction
from hathor.transaction.storage import TransactionStorage
from hathor.util import collect_n

_DEFAULT_MAX_CHILDREN = 20


class GraphvizVisualizer:
    def __init__(
        self,
        storage: TransactionStorage,
        include_funds: bool = False,
        include_verifications: bool = False,
        only_blocks: bool = False,
        max_children: int = _DEFAULT_MAX_CHILDREN,
    ):
        self._settings = get_global_settings()
        self.storage = storage

        # Indicate whether it should show fund edges
        self.include_funds = include_funds

        # Indicate whether it should show verification edges
        self.include_verifications = include_verifications

        # Indicate whether it should only show blocks
        self.only_blocks = only_blocks

        # Show weights in node's label
        self.show_weight = False

        # Show acc_weights in node's label
        self.show_acc_weight = False

        # Attributes
        self.block_attrs = dict(shape='box', style='filled', fillcolor='#EC644B')
        self.genesis_attrs = dict(fillcolor='#87D37C', style='filled')
        self.tx_tips_attrs = dict(style='filled', fillcolor='#F5D76E')
        self.voided_attrs = dict(style='dashed,filled', penwidth='0.25', fillcolor='#BDC3C7')
        self.soft_voided_attrs = dict(style='dashed,filled', penwidth='0.25', fillcolor='#CCCCFF')
        self.conflict_attrs = dict(style='dashed,filled', penwidth='2.0', fillcolor='#BDC3C7')
        self.not_fully_validated_attrs = dict(style='dashed,filled', penwidth='0.25', fillcolor='#F9FFAB')

        # Labels
        self.labels: dict[bytes, str] = {}

        # Internals
        self._blocks_set: set[bytes] = set()
        self._txs_set: set[bytes] = set()

        self.MAX_CHILDREN = max_children

    def get_node_label(self, tx: BaseTransaction) -> str:
        """ Return the node's label for tx.
        """
        if tx.hash in self.labels:
            parts = [self.labels[tx.hash]]
        elif tx.name is not None:
            parts = [tx.name]
        else:
            parts = [tx.hash.hex()[-4:]]

        if self.show_weight:
            parts.append('w: {:.2f}'.format(tx.weight))
        if self.show_acc_weight:
            meta = tx.get_metadata()
            parts.append('a: {:.2f}'.format(meta.accumulated_weight))
        return '\n'.join(parts)

    def get_node_attrs(self, tx: BaseTransaction) -> dict[str, str]:
        """ Return node's attributes.
        """
        node_attrs = {'label': self.get_node_label(tx)}

        if tx.is_block:
            node_attrs.update(self.block_attrs)
        if tx.is_genesis:
            node_attrs.update(self.genesis_attrs)

        meta = tx.get_metadata()
        if meta.voided_by and len(meta.voided_by) > 0:
            if meta.voided_by and tx.hash in meta.voided_by:
                node_attrs.update(self.conflict_attrs)
            if self._settings.SOFT_VOIDED_ID in meta.voided_by:
                node_attrs.update(self.soft_voided_attrs)
            else:
                node_attrs.update(self.voided_attrs)

        if not meta.validation.is_fully_connected():
            node_attrs.update(self.not_fully_validated_attrs)

        return node_attrs

    def get_edge_attrs(self, tx: BaseTransaction, neighbor_hash: bytes) -> dict[str, str]:
        """ Return edge's attributes.
        """
        edge_attrs = {}
        if neighbor_hash in self._blocks_set:
            edge_attrs.update(dict(penwidth='3'))
        else:
            edge_attrs.update(dict(penwidth='1'))
        return edge_attrs

    def get_parent_edge_attrs(self, tx: BaseTransaction, neighbor_hash: bytes) -> dict[str, str]:
        """ Return edge's attributes for a verification edge.
        """
        return self.get_edge_attrs(tx, neighbor_hash)

    def get_input_edge_attrs(self, tx: BaseTransaction, neighbor_hash: bytes) -> dict[str, str]:
        """ Return edge's attributes for a fund edge.
        """
        edge_attrs = self.get_edge_attrs(tx, neighbor_hash)
        edge_attrs['style'] = 'dashed'
        return edge_attrs

    def get_nodes_iterator(self) -> Iterator[BaseTransaction]:
        """ Return an iterator.
        """
        # TODO: check if it's safe to use one of the two faster iterators
        return self.storage._topological_sort_dfs()

    def dot(self, format: str = 'pdf') -> Digraph:
        """Return a Graphviz object of the DAG of verifications.

        :param format: Format of the visualization (pdf, png, or jpg)
        :return: A Graphviz object
        """
        dot = Digraph(format=format)
        dot.attr('node', shape='oval', style='')

        self._blocks_set = set()  # set[bytes(hash)]
        self._txs_set = set()  # set[bytes(hash)]

        g_blocks = dot.subgraph(name='blocks')
        g_txs = dot.subgraph(name='txs')
        g_genesis = dot.subgraph(name='genesis')
        with g_genesis as g_g, g_txs as g_t, g_blocks as g_b:

            nodes_iter = self.get_nodes_iterator()
            for i, tx in enumerate(nodes_iter):
                if self.only_blocks and not tx.is_block:
                    continue

                name = tx.hash.hex()

                node_attrs = self.get_node_attrs(tx)

                if tx.is_genesis:
                    g_g.node(name, **node_attrs)
                elif tx.is_block:
                    g_b.node(name, **node_attrs)
                else:
                    g_t.node(name, **node_attrs)

                for txin in tx.inputs:
                    edge_attrs = self.get_input_edge_attrs(tx, txin.tx_id)
                    if not self.include_funds:
                        # If user does not want to see the edge of funds, we just hide them.
                        edge_attrs['style'] = 'invis'
                    dot.edge(name, txin.tx_id.hex(), **edge_attrs)

                if self.include_verifications:
                    for parent_hash in tx.parents:
                        if self.only_blocks and parent_hash not in self._blocks_set:
                            continue
                        edge_attrs = self.get_parent_edge_attrs(tx, parent_hash)
                        dot.edge(name, parent_hash.hex(), **edge_attrs)

                if tx.is_block:
                    self._blocks_set.add(tx.hash)
                else:
                    self._txs_set.add(tx.hash)

        dot.attr(rankdir='RL')
        dot.attr(overlap='scale')
        return dot

    def tx_neighborhood(self, tx: BaseTransaction, format: str = 'pdf',
                        max_level: int = 2, graph_type: str = 'verification') -> Digraph:
        """ Draw the blocks and transactions around `tx`.

        :params max_level: Maximum distance between `tx` and the others.
        :params graph_type: Graph type to be generated. Possibilities are 'verification' and 'funds'
        """
        dot = Digraph(format=format)
        dot.attr(rankdir='RL')

        dot.attr('node', shape='oval', style='')

        root = tx
        to_visit = [(0, tx)]
        seen = set([tx.hash])

        while to_visit:
            level, tx = to_visit.pop()
            assert tx.storage is not None
            name = tx.hash.hex()
            node_attrs = self.get_node_attrs(tx)

            if tx.hash == root.hash:
                node_attrs.update(dict(style='filled', penwidth='5.0'))

            meta = tx.get_metadata()
            limited_children, has_more_children = collect_n(iter(tx.get_children()), self.MAX_CHILDREN)

            if graph_type == 'verification':
                if tx.is_block:
                    continue

                dot.node(name, **node_attrs)

                if level <= max_level:
                    for h in chain(tx.parents, limited_children):
                        if h not in seen:
                            seen.add(h)
                            tx2 = tx.storage.get_transaction(h)
                            to_visit.append((level + 1, tx2))

                    if has_more_children:
                        extra_children_id = f'{tx.hash_hex}_extra_children'
                        dot.node(extra_children_id, label='more children')
                        dot.edge(extra_children_id, name)

                for h in tx.parents:
                    if h in seen:
                        dot.edge(name, h.hex())

            elif graph_type == 'funds':
                dot.node(name, **node_attrs)

                if level <= max_level:
                    spent_outputs_ids = chain.from_iterable(meta.spent_outputs.values())
                    tx_input_ids = [txin.tx_id for txin in tx.inputs]
                    for h in chain(tx_input_ids, spent_outputs_ids):
                        if h not in seen:
                            seen.add(h)
                            tx2 = tx.storage.get_transaction(h)
                            to_visit.append((level + 1, tx2))

                for txin in tx.inputs:
                    if txin.tx_id in seen:
                        dot.edge(name, txin.tx_id.hex())

        return dot
