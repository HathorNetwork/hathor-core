# encoding: utf-8
from hathor.transaction.storage.exceptions import TransactionIsNotABlock

from collections import deque


class TransactionStorage:
    def __init__(self):
        self._reset_cache()
        if self.__class__ == TransactionStorage:
            raise Exception('You cannot directly create an instance of this class.')

    def _reset_cache(self):
        """Reset all caches. This function should not be called unless you know
        what you are doing.
        """
        self._cache_tips = {}  # Dict[bytes(hash), bool(is_block)]
        self._cache_block_count = 0
        self._cache_tx_count = 0

    def _manually_initialize(self):
        """Caches must be initialized. This function should not be called, because
        usually the HathorManager will handle all this initialization.
        """
        self._reset_cache()

        # We need to construct a topological sort, then iterate from
        # genesis to tips.
        for tx in self._topological_sort():
            self._add_to_cache(tx)

    def _topological_sort(self):
        """Return an iterable of the transactions in topological ordering, i.e., from
        genesis to the most recent transactions. The order is important because the
        transactions are always valid---their parents and inputs exist.

        :return: An iterable with the sorted transactions
        :rtype: Iterable[BaseTransaction]
        """
        # TODO We must optimize this algorithm to remove the `visited` set.
        #      It will consume too much memory when the number of transactions is big.
        #      A solution would be to store the ordering in disk, probably indexing by tx's height.
        #      Sorting the vertices by the lengths of their longest incoming paths produces a topological
        #      ordering (Dekel, Nassimi & Sahni 1981). See: https://epubs.siam.org/doi/10.1137/0210049
        #      See also: https://gitlab.com/HathorNetwork/hathor-python/merge_requests/31
        visited = set()  # Set[bytes(hash)]
        cnt = 0
        for tx in self.get_all_transactions():
            cnt += 1
            yield from self._topological_sort_dfs(tx, visited)

    def _topological_sort_dfs(self, root, visited):
        if root.hash in visited:
            return

        stack = [root]
        visited.add(root.hash)
        while stack:
            tx = stack[-1]
            is_leaf = True
            for parent_hash in tx.parents:
                if parent_hash not in visited:
                    is_leaf = False
                    visited.add(parent_hash)
                    parent = self.get_transaction_by_hash_bytes(parent_hash)
                    stack.append(parent)
            if is_leaf:
                assert tx == stack.pop()
                yield tx

    def _add_to_cache(self, tx):
        for parent_hash in tx.parents:
            if parent_hash in self._cache_tips:
                self._cache_tips.pop(parent_hash)
        self._cache_tips[tx.hash] = tx.is_block
        if tx.is_block:
            self._cache_block_count += 1
        else:
            self._cache_tx_count += 1

    def get_block_count(self):
        return self._cache_block_count

    def get_tx_count(self):
        return self._cache_tx_count

    def save_transaction(self, tx):
        self._add_to_cache(tx)

    def transaction_exists_by_hash(self, hash_hex):
        raise NotImplementedError

    def transaction_exists_by_hash_bytes(self, hash_bytes):
        raise NotImplementedError

    def get_transaction_by_hash_bytes(self, hash_bytes):
        raise NotImplementedError

    def get_transaction_by_hash(self, hash_hex):
        raise NotImplementedError

    def update_metadata(self, hash_hex, data):
        raise NotImplementedError

    def get_metadata_by_hash(self, hash_hex):
        raise NotImplementedError

    def get_metadata_by_hash_bytes(self, hash_bytes):
        raise NotImplementedError

    def get_genesis_by_hash_bytes(self, hash_bytes):
        """
            Returning hardcoded genesis block and transactions
        """
        from hathor.transaction.genesis import genesis_transactions
        for genesis in genesis_transactions(self):
            if hash_bytes == genesis.hash:
                return genesis

        return None

    def get_all_transactions(self):
        raise NotImplementedError

    def get_count_tx_blocks(self):
        raise NotImplementedError

    def get_tip_blocks(self):
        ret = []  # List[bytes(hash)]
        for h, is_block in self._cache_tips.items():
            if is_block:
                ret.append(h)
        return ret

    def get_latest_block(self):
        blocks = self.get_latest_blocks(5)

        assert blocks, 'No tip blocks available, not even genesis!'

        sorted_blocks = sorted(blocks, key=lambda b: b.height, reverse=True)
        return sorted_blocks[0]

    def get_best_height(self):
        """Returns the height for the most recent block."""
        latest_block = self.get_latest_block()
        return latest_block.height

    def get_latest_blocks(self, count=2):
        # XXX Just for testing, transforming generator into list would be impossible with many transactions
        blocks = list(tx for tx in self.get_all_transactions() if tx.is_block)
        blocks = sorted(blocks, key=lambda t: t.timestamp, reverse=True)
        return blocks[:count]

    def get_blocks_at_height(self, height):
        """Returns a list of all stored block objects with the given height."""
        raise NotImplementedError

    def get_block_hashes_at_height(self, height):
        """Returns a list of all stored block objects with the given height."""
        raise NotImplementedError

    def get_blocks_before(self, hash_hex, num_blocks=100):
        """Run a BFS starting from the giving `hash_hex`.

        :param hash_hex: Starting point of the BFS.
        :type hash_hex: string(hex)

        :param num_blocks: Number of blocks to be return.
        :type num_blocks: int
        """
        ref_tx = self.get_transaction_by_hash(hash_hex)
        if not ref_tx.is_block:
            raise TransactionIsNotABlock
        result = []  # List[Block]
        pending_visits = deque(ref_tx.parents)  # List[bytes(hash)]
        used = set(pending_visits)  # Set([bytes(hash)])
        while pending_visits:
            tx_hash = pending_visits.popleft()
            tx = self.get_transaction_by_hash_bytes(tx_hash)
            if not tx.is_block:
                continue
            result.append(tx)
            if len(result) >= num_blocks:
                break
            for parent_hash in tx.parents:
                if parent_hash not in used:
                    used.add(parent_hash)
                    pending_visits.append(parent_hash)
        return result

    def get_block_hashes_after(self, hash_hex, num_blocks=100):
        """Retrieve the next num_blocks block hashes after the given hash. Return value is a list of hashes."""
        hashes = []
        tx = self.get_transaction_by_hash(hash_hex)
        if not tx.is_block:
            raise TransactionIsNotABlock
        for i in range(tx.height + 1, tx.height + 1 + num_blocks):
            for h in self.get_block_hashes_at_height(i):
                hashes.append(h)
        return hashes

    def get_tip_transactions(self, count=2):
        tips = self.get_latest_transactions(count)
        ret = []
        for tx in tips:
            ret.append(tx.hash)
        return ret

    def get_all_genesis(self):
        from hathor.transaction.genesis import genesis_transactions
        return genesis_transactions(self)

    def get_latest(self, transactions, count=2, page=1):
        transactions = sorted(transactions, key=lambda t: t.timestamp, reverse=True)

        # Calculating indexes based on count and page
        start_index = (page - 1) * count
        end_index = start_index + count
        return transactions[start_index:end_index]

    def get_latest_transactions(self, count=2, page=1):
        # XXX Just for testing, transforming generator into list would be impossible with many transactions
        transactions = list(tx for tx in self.get_all_transactions() if not tx.is_block)
        return self.get_latest(transactions=transactions, count=count, page=page)

    def get_latest_tx_blocks(self, count=2, page=1):
        # XXX Just for testing, transforming generator into list would be impossible with many transactions
        transactions = list(tx for tx in self.get_all_transactions())
        return self.get_latest(transactions=transactions, count=count, page=page)

    def graphviz(self, format='pdf'):
        """Return a Graphviz object that can be rendered to generate a visualization of the DAG.

        :param format: Format of the visualization (pdf, png, or jpg)
        :type format: string

        :return: A Graphviz object
        :rtype: :py:class:`graphviz.Digraph`
        """
        from graphviz import Digraph

        dot = Digraph(format=format)

        g_blocks = dot.subgraph(name='blocks')
        g_txs = dot.subgraph(name='txs')
        g_genesis = dot.subgraph(name='genesis')

        tx_tips_attrs = dict(style='filled', fillcolor='#F5D76E')
        block_attrs = dict(shape='box', style='filled', fillcolor='#EC644B')

        dot.attr('node', shape='oval', style='')
        nodes_iter = self._topological_sort()
        for i, tx in enumerate(nodes_iter):
            name = tx.hash.hex()
            attrs_node = {'label': tx.hash.hex()[-4:]}
            attrs_edge = {}

            if tx.is_block:
                attrs_node.update(block_attrs)
                attrs_edge.update(dict(pendiwth='4'))

            if tx.hash in self._cache_tips:
                attrs_node.update(tx_tips_attrs)

            if tx.is_genesis:
                attrs_node.update(dict(fillcolor='#87D37C', style='filled'))
                with g_genesis as c:
                    c.node(name, **attrs_node)
            elif tx.is_block:
                with g_blocks as c:
                    c.node(name, **attrs_node)
            else:
                with g_txs as c:
                    c.node(name, **attrs_node)

            for parent_hash in tx.parents:
                dot.edge(name, parent_hash.hex(), **attrs_edge)

        dot.attr(rankdir='RL')
        return dot
