# encoding: utf-8
from hathor.transaction.storage.exceptions import TransactionIsNotABlock

from collections import deque
import random


class TransactionStorage:
    def __init__(self):
        self._reset_cache()
        if self.__class__ == TransactionStorage:
            raise Exception('You cannot directly create an instance of this class.')

    def _reset_cache(self):
        """Reset all caches. This function should not be called unless you know
        what you are doing.
        """
        self._cache_tip_blocks = {}        # Dict[bytes(hash), Block]
        self._cache_tip_transactions = {}  # Dict[bytes(hash), Transaction]
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
        visited = dict()  # Set[bytes(hash), int]
        cnt = 0
        for tx in self.get_all_transactions():
            cnt += 1
            yield from self._topological_sort_dfs(tx, visited)

    def _topological_sort_dfs(self, root, visited):
        if root.hash in visited:
            return

        stack = [root]
        while stack:
            tx = stack[-1]
            if tx.hash in visited:
                if visited[tx.hash] == 0:
                    visited[tx.hash] = 1  # 1 = Visited
                    yield tx
                assert tx == stack.pop()
                continue

            visited[tx.hash] = 0  # 0 = Visit in progress

            for txin in tx.inputs:
                if txin.tx_id not in visited:
                    txinput = self.get_transaction_by_hash_bytes(txin.tx_id)
                    stack.append(txinput)

            for parent_hash in tx.parents:
                if parent_hash not in visited:
                    parent = self.get_transaction_by_hash_bytes(parent_hash)
                    stack.append(parent)

    def iter_bfs(self, root):
        """Run a BFS starting from the giving transaction.

        :param root: Starting point of the BFS, either a block or a transaction.
        :type root: :py:class:`hathor.transaction.BaseTransaction`

        :return: An iterable with the transactions
        :rtype: Iterable[BaseTransaction]
        """
        to_visit = deque(root.parents)  # List[bytes(hash)]
        seen = set(to_visit)    # Set[bytes(hash)]

        while to_visit:
            tx_hash = to_visit.popleft()
            tx = self.get_transaction_by_hash_bytes(tx_hash)
            yield tx
            seen.add(tx_hash)
            for parent_hash in tx.parents:
                if parent_hash not in seen:
                    to_visit.append(parent_hash)
                    seen.add(parent_hash)

    def _add_to_cache(self, tx):
        if tx.is_block:
            self._cache_block_count += 1
            cache = self._cache_tip_blocks
        else:
            self._cache_tx_count += 1
            cache = self._cache_tip_transactions

        for parent_hash in tx.parents:
            if parent_hash in cache:
                cache.pop(parent_hash)
        cache[tx.hash] = tx

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

    def save_metadata(self, metadata):
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
        """
        Return the blocks which have not been confirmed yet.

        :return: A list of blocks.
        :rtype: List[Block]
        """
        return list(self._cache_tip_blocks.values())

    def get_tip_blocks_hashes(self):
        """
        Return the hashes of the blocks which have not been confirmed yet.

        :return: A list of block hashes.
        :rtype: List[bytes(hash)]
        """
        return list(self._cache_tip_blocks.keys())

    def get_tip_transactions(self, count=None):
        """
        Return the transactions which have not been confirmed yet.

        :return: A list of transactions.
        :type: List[Transaction]
        """
        ret = list(self._cache_tip_transactions.values())
        if count is None:
            return ret
        # If there are many tip transactions, we randomly choose among them.
        # Instead of implementing an algorithm to choose without repetition,
        # I just shuffled the options and get the firsts. Another approach
        # would be to stop shuffling after `count` steps.
        random.shuffle(ret)
        return ret[:count]

    def get_tip_transactions_hashes(self, count=None):
        """
        Return the hashes of the transactions which have not been confirmed yet.

        :return: A list of transaction hashes.
        :type: List[bytes(hash)]
        """
        ret = list(self._cache_tip_transactions.keys())
        if count is None:
            return ret
        random.shuffle(ret)
        return ret[:count]

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

    def get_transactions_before(self, hash_hex, num_blocks=100):
        """Run a BFS starting from the giving `hash_hex`.

        :param hash_hex: Starting point of the BFS, either a block or a transaction.
        :type hash_hex: string(hex)

        :param num_blocks: Number of blocks to be return.
        :type num_blocks: int
        """
        ref_tx = self.get_transaction_by_hash(hash_hex)
        visited = dict()  # Set[bytes(hash), int]
        result = [x for x in self._topological_sort_dfs(ref_tx, visited) if not x.is_block]
        result = result[-num_blocks:]
        return result

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

    def get_txs_after_hash(self, ref_hash=None, count=10):
        """ Returns transactions after the ref_hash (quantity is defined by count parameter)
            If ref_hash is not passed, we get the first (count) transactions

            :param ref_hash: Hash in hex passed as reference, so we can return the transactions after this one
            :type format: string

            :param count: Quantity of transactions to return
            :type format: int

            :return: List of transactions and a boolean indicating if there are more txs after
            :rtype: tuple[list[Transaction], bool]
        """
        txs = list(tx for tx in self.get_all_transactions() if not tx.is_block)
        return self.get_all_after_hash(txs, ref_hash, count)

    def get_blocks_after_hash(self, ref_hash=None, count=10):
        """ Returns blocks after the ref_hash (quantity is defined by count parameter)
            If ref_hash is not passed, we get the first (count) blocks

            :param ref_hash: Hash in hex passed as reference, so we can return the blocks after this one
            :type format: string

            :param count: Quantity of blocks to return
            :type format: int

            :return: List of blocks and a boolean indicating if there are more blocks after
            :rtype: tuple[list[Block], bool]
        """
        blocks = list(block for block in self.get_all_transactions() if block.is_block)
        return self.get_all_after_hash(blocks, ref_hash, count)

    def get_all_after_hash(self, transactions, ref_hash, count):
        """ Receives the list of elements (txs or blocks) to be paginated.
            We first order the elements by timestamp and then
            If ref_hash is None, we return the first count elements
            If ref_hash is not None, we calculate the elements after ref_hash and if we still have more

            :param transactions: List of elements we need to paginate
            :type format: list[Block, Transaction]

            :param ref_hash: Hash in hex passed as reference, so we can return the blocks after this one
            :type format: string

            :param count: Quantity of elements to return
            :type format: int

            :return: List of blocks or txs and a boolean indicating if there are more blocks before
            :rtype: tuple[list[Block, Transaction], bool]
        """
        # XXX This method is not optimized, we need to improve this search
        txs = sorted(transactions, key=lambda t: t.timestamp, reverse=True)

        total = len(txs)

        if not ref_hash:
            return txs[:count], total > count
        else:
            for idx, tx in enumerate(txs):
                if tx.hash.hex() == ref_hash:
                    start_idx = idx + 1
                    end_idx = start_idx + count
                    return txs[start_idx:end_idx], total > end_idx

    def get_txs_before_hash(self, ref_hash, count=10):
        """ Returns transactions before the ref_hash (quantity is defined by count parameter)

            :param ref_hash: Hash in hex passed as reference, so we can return the txs before this one
            :type format: string

            :param count: Quantity of txs to return
            :type format: int

            :return: List of transactions and a boolean indicating if there are more transactions before
            :rtype: tuple[list[Transaction], bool]
        """
        txs = list(tx for tx in self.get_all_transactions() if not tx.is_block)
        return self.get_all_before_hash(txs, ref_hash, count)

    def get_blocks_before_hash(self, ref_hash, count=10):
        """ Returns blocks before the ref_hash (quantity is defined by count parameter)

            :param ref_hash: Hash in hex passed as reference, so we can return the blocks before this one
            :type format: string

            :param count: Quantity of blocks to return
            :type format: int

            :return: List of blocks and a boolean indicating if there are more blocks before
            :rtype: tuple[list[Block], bool]
        """
        blocks = list(block for block in self.get_all_transactions() if block.is_block)
        return self.get_all_before_hash(blocks, ref_hash, count)

    def get_all_before_hash(self, transactions, ref_hash, count):
        """ Receives the list of elements (txs or blocks) to be paginated.
            We first order the elements by timestamp and then
            We calculate the elements before ref_hash and if we still have more before it

            :param transactions: List of elements we need to paginate
            :type format: list[Block, Transaction]

            :param ref_hash: Hash in hex passed as reference, so we can return the blocks before this one
            :type format: string

            :param count: Quantity of elements to return
            :type format: int

            :return: List of blocks or txs and a boolean indicating if there are more blocks before
            :rtype: tuple[list[Block, Transaction], bool]
        """
        # XXX This method is not optimized, we need to improve this search
        txs = sorted(transactions, key=lambda t: t.timestamp, reverse=True)

        for idx, tx in enumerate(txs):
            if tx.hash.hex() == ref_hash:
                start_idx = max(0, idx - count)
                return txs[start_idx:idx], start_idx > 0

    def graphviz(self, format='pdf', weight=False, acc_weight=False):
        """Return a Graphviz object that can be rendered to generate a visualization of the DAG.

        :param format: Format of the visualization (pdf, png, or jpg)
        :type format: string

        :param weight: Whether to display or not the tx weight
        :type format: bool

        :param acc_weight: Whether to display or not the tx accumulated weight
        :type format: bool

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

        with g_genesis as g_g, g_txs as g_t, g_blocks as g_b:
            for i, tx in enumerate(nodes_iter):
                name = tx.hash.hex()
                attrs_node = {'label': tx.hash.hex()[-4:]}
                attrs_edge = {}

                if tx.is_block:
                    attrs_node.update(block_attrs)
                    attrs_edge.update(dict(pendiwth='4'))

                if (tx.hash in self._cache_tip_blocks) or (tx.hash in self._cache_tip_transactions):
                    attrs_node.update(tx_tips_attrs)

                if weight:
                    attrs_node.update(dict(label='{}\nw: {:.2f}'.format(attrs_node['label'], tx.weight)))

                if acc_weight:
                    metadata = tx.get_metadata()
                    attrs_node.update(
                        dict(label='{}\naw: {:.2f}'.format(attrs_node['label'], metadata.accumulated_weight))
                    )

                if tx.is_genesis:
                    attrs_node.update(dict(fillcolor='#87D37C', style='filled'))
                    g_g.node(name, **attrs_node)
                elif tx.is_block:
                    g_b.node(name, **attrs_node)
                else:
                    g_t.node(name, **attrs_node)

                for parent_hash in tx.parents:
                    dot.edge(name, parent_hash.hex(), **attrs_edge)

        dot.attr(rankdir='RL')
        return dot
