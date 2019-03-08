
from itertools import chain

from graphviz import Digraph

from hathor.transaction import BaseTransaction, Block
from hathor.transaction.storage import TransactionStorage


def blockchain(tx_storage: TransactionStorage, format: str = 'pdf'):
    """ Draw only the blocks and their connections.
    It goes through all transactions. So, take care with performance.
    """
    dot = Digraph(format=format)
    dot.attr(rankdir='RL')

    for tx in tx_storage.get_all_transactions():
        assert tx.hash is not None

        if not tx.is_block:
            continue
        assert isinstance(tx, Block)

        name = tx.hash.hex()
        node_attrs = get_node_attrs(tx)
        dot.node(name, **node_attrs)

        if len(tx.parents) > 0:
            dot.edge(name, tx.get_block_parent_hash().hex())

    return dot


def tx_neighborhood(tx: BaseTransaction, format: str = 'pdf',
                    max_level: int = 2, graph_type: str = 'verification') -> Digraph:
    """ Draw the blocks and transactions around `tx`.

    :params max_level: Maximum distance between `tx` and the others.
    :params graph_type: Graph type to be generated. Possibilities are 'verification' and 'funds'
    """
    dot = Digraph(format=format)
    dot.attr(rankdir='RL')

    dot.attr('node', shape='oval', style='')
    # attrs_node = {'label': tx.hash.hex()[-4:]}

    root = tx
    to_visit = [(0, tx)]
    seen = set([tx.hash])

    while to_visit:
        level, tx = to_visit.pop()
        assert tx.hash is not None
        assert tx.storage is not None
        name = tx.hash.hex()
        node_attrs = get_node_attrs(tx)

        if tx.hash == root.hash:
            node_attrs.update(dict(style='filled', penwidth='5.0'))

        dot.node(name, **node_attrs)

        meta = tx.get_metadata()

        if graph_type == 'verification':

            if level <= max_level:
                for h in chain(tx.parents, meta.children):
                    if h not in seen:
                        seen.add(h)
                        tx2 = tx.storage.get_transaction(h)
                        to_visit.append((level + 1, tx2))

            for h in tx.parents:
                if h in seen:
                    dot.edge(name, h.hex())
        elif graph_type == 'funds':
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


def verifications(storage: TransactionStorage, format: str = 'pdf', weight: bool = False, acc_weight: bool = False,
                  block_only: bool = False) -> Digraph:
    """Return a Graphviz object of the DAG of verifications.

    :param format: Format of the visualization (pdf, png, or jpg)
    :param weight: Whether to display or not the tx weight
    :param acc_weight: Whether to display or not the tx accumulated weight
    :return: A Graphviz object
    """
    dot = Digraph(format=format)
    dot.attr('node', shape='oval', style='')

    g_blocks = dot.subgraph(name='blocks')
    g_txs = dot.subgraph(name='txs')
    g_genesis = dot.subgraph(name='genesis')

    blocks_set = set()  # Set[bytes(hash)]
    txs_set = set()  # Set[bytes(hash)]

    nodes_iter = storage._topological_sort()
    with g_genesis as g_g, g_txs as g_t, g_blocks as g_b:
        for i, tx in enumerate(nodes_iter):
            assert tx.hash is not None
            name = tx.hash.hex()

            attrs_node = get_node_attrs(tx)
            attrs_edge = {}

            if block_only and not tx.is_block:
                continue

            if tx.is_block:
                blocks_set.add(tx.hash)
            else:
                txs_set.add(tx.hash)

            if weight:
                attrs_node.update(dict(label='{}\nw: {:.2f}'.format(attrs_node['label'], tx.weight)))

            if acc_weight:
                metadata = tx.get_metadata()
                attrs_node.update(
                    dict(label='{}\naw: {:.2f}'.format(attrs_node['label'], metadata.accumulated_weight)))

            if tx.is_genesis:
                g_g.node(name, **attrs_node)
            elif tx.is_block:
                g_b.node(name, **attrs_node)
            else:
                g_t.node(name, **attrs_node)

            for parent_hash in tx.parents:
                if block_only and parent_hash not in blocks_set:
                    continue
                if parent_hash in blocks_set:
                    attrs_edge.update(dict(penwidth='3'))
                else:
                    attrs_edge.update(dict(penwidth='1'))
                dot.edge(name, parent_hash.hex(), **attrs_edge)

    dot.attr(rankdir='RL')
    return dot


def funds(storage: TransactionStorage, format: str = 'pdf', weight: bool = False, acc_weight: bool = False) -> Digraph:
    """Return a Graphviz object of the DAG of funds.

    :param format: Format of the visualization (pdf, png, or jpg)
    :param weight: Whether to display or not the tx weight
    :param acc_weight: Whether to display or not the tx accumulated weight
    :return: A Graphviz object
    """
    dot = Digraph(format=format)
    dot.attr('node', shape='oval', style='')

    g_blocks = dot.subgraph(name='blocks')
    g_txs = dot.subgraph(name='txs')
    g_genesis = dot.subgraph(name='genesis')

    nodes_iter = storage._topological_sort()
    with g_genesis as g_g, g_txs as g_t, g_blocks as g_b:
        for i, tx in enumerate(nodes_iter):
            assert tx.hash is not None
            name = tx.hash.hex()
            attrs_node = get_node_attrs(tx)
            attrs_edge = {}

            if tx.is_block:
                attrs_edge.update(dict(penwidth='4'))

            if weight:
                attrs_node.update(dict(label='{}\nw: {:.2f}'.format(attrs_node['label'], tx.weight)))

            if acc_weight:
                metadata = tx.get_metadata()
                attrs_node.update(
                    dict(label='{}\naw: {:.2f}'.format(attrs_node['label'], metadata.accumulated_weight)))

            if tx.is_genesis:
                g_g.node(name, **attrs_node)
            elif tx.is_block:
                g_b.node(name, **attrs_node)
            else:
                g_t.node(name, **attrs_node)

            for txin in tx.inputs:
                dot.edge(name, txin.tx_id.hex(), **attrs_edge)

    dot.attr(rankdir='RL')
    return dot


def get_node_attrs(tx: BaseTransaction):
    assert tx.hash is not None

    # tx_tips_attrs = dict(style='filled', fillcolor='#F5D76E')
    block_attrs = dict(shape='box', style='filled', fillcolor='#EC644B')

    voided_attrs = dict(style='dashed,filled', penwidth='0.25', fillcolor='#BDC3C7')
    conflict_attrs = dict(style='dashed,filled', penwidth='2.0', fillcolor='#BDC3C7')

    attrs_node = {'label': tx.hash.hex()[-4:]}

    if tx.is_block:
        attrs_node.update(block_attrs)
    if tx.is_genesis:
        attrs_node.update(dict(fillcolor='#87D37C', style='filled'))

    meta = tx.get_metadata()
    if meta.voided_by:
        attrs_node.update(voided_attrs)
        if tx.hash in meta.voided_by:
            attrs_node.update(conflict_attrs)

    return attrs_node
