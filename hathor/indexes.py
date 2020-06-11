"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from collections import defaultdict
from math import inf
from typing import TYPE_CHECKING, DefaultDict, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple, cast

from intervaltree import Interval, IntervalTree
from sortedcontainers import SortedKeyList
from structlog import get_logger

from hathor.pubsub import HathorEvents
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.base_transaction import TxVersion
from hathor.transaction.scripts import parse_address_script

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import EventArguments, PubSubManager  # noqa: F401
    from hathor.transaction import TxOutput  # noqa: F401

logger = get_logger()


class TransactionIndexElement(NamedTuple):
    timestamp: int
    hash: bytes


class IndexesManager:
    """ IndexesManager manages all the indexes that we will have in the system

        The ideia is for the manager to handle all method calls to indexes,
        so it will know which index is better to use in each moment
    """

    def __init__(self) -> None:
        self.tips_index = TipsIndex()
        self.txs_index = TransactionsIndex()

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a transaction to the indexes

        :param tx: Transaction to be added
        """
        r1 = self.tips_index.add_tx(tx)
        r2 = self.txs_index.add_tx(tx)
        assert r1 == r2
        return r1

    def del_tx(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        """
        self.tips_index.del_tx(tx, relax_assert=relax_assert)
        self.txs_index.del_tx(tx)

    def get_newest(self, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks in txs_index from the newest to the oldest

        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return self.txs_index.get_newest(count)

    def get_older(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks in txs_index from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return self.txs_index.get_older(timestamp, hash_bytes, count)

    def get_newer(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks in txs_index from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return self.txs_index.get_newer(timestamp, hash_bytes, count)


class TipsIndex:
    """ Use an interval tree to quick get the tips at a given timestamp.

    The interval of a transaction is in the form [begin, end), where `begin` is
    the transaction's timestamp, and `end` is when it was first verified by another
    transaction.

    If a transaction is still a tip, `end` is equal to infinity.

    If a transaction has been verified many times, `end` is equal to `min(tx.timestamp)`.

    TODO Use an interval tree stored in disk, possibly using a B-tree.
    """

    # An interval tree used to know the tips at any timestamp.
    # The intervals are in the form (begin, end), where begin is the timestamp
    # of the transaction, and end is the smallest timestamp of the tx's children.
    tree: IntervalTree

    # It is a way to access the interval by the hash of the transaction.
    # It is useful because the interval tree allows access only by the interval.
    tx_last_interval: Dict[bytes, Interval]

    def __init__(self) -> None:
        self.log = logger.new()
        self.tree = IntervalTree()
        self.tx_last_interval = {}  # Dict[bytes(hash), Interval]

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a new transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.hash is not None
        assert tx.storage is not None
        if tx.hash in self.tx_last_interval:
            return False

        # Fix the end of the interval of its parents.
        for parent_hash in tx.parents:
            pi = self.tx_last_interval.get(parent_hash, None)
            if not pi:
                continue
            if tx.timestamp < pi.end:
                self.tree.remove(pi)
                new_interval = Interval(pi.begin, tx.timestamp, pi.data)
                self.tree.add(new_interval)
                self.tx_last_interval[parent_hash] = new_interval

        # Check whether any children has already been added.
        # It so, the end of the interval is equal to the smallest timestamp of the children.
        min_timestamp = inf
        meta = tx.get_metadata()
        for child_hash in meta.children:
            if child_hash in self.tx_last_interval:
                child = tx.storage.get_transaction(child_hash)
                min_timestamp = min(min_timestamp, child.timestamp)

        # Add the interval to the tree.
        interval = Interval(tx.timestamp, min_timestamp, tx.hash)
        self.tree.add(interval)
        self.tx_last_interval[tx.hash] = interval
        return True

    def del_tx(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        """ Remove a transaction from the index.
        """
        assert tx.hash is not None
        assert tx.storage is not None

        interval = self.tx_last_interval.pop(tx.hash, None)
        if interval is None:
            return

        if not relax_assert:
            assert interval.end == inf

        self.tree.remove(interval)

        # Update its parents as tips if needed.
        # FIXME Although it works, it does not seem to be a good solution.
        for parent_hash in tx.parents:
            parent = tx.storage.get_transaction(parent_hash)
            if parent.is_block != tx.is_block:
                continue
            self.update_tx(parent, relax_assert=relax_assert)

    def update_tx(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        """ Update a tx according to its children.
        """
        assert tx.storage is not None
        assert tx.hash is not None

        meta = tx.get_metadata()
        if meta.voided_by:
            if not relax_assert:
                assert tx.hash not in self.tx_last_interval
            return

        pi = self.tx_last_interval[tx.hash]

        min_timestamp = inf
        for child_hash in meta.children:
            if child_hash in self.tx_last_interval:
                child = tx.storage.get_transaction(child_hash)
                min_timestamp = min(min_timestamp, child.timestamp)

        if min_timestamp != pi.end:
            self.tree.remove(pi)
            new_interval = Interval(pi.begin, min_timestamp, pi.data)
            self.tree.add(new_interval)
            self.tx_last_interval[tx.hash] = new_interval

    def __getitem__(self, index: float) -> Set[Interval]:
        return self.tree[index]


def get_newest_sorted_key_list(key_list: 'SortedKeyList[TransactionIndexElement]', count: int
                               ) -> Tuple[List[bytes], bool]:
    """ Get newest data from a sorted key list
        Return the elements (quantity is the 'count' parameter) and a boolean indicating if has more
    """
    newest = key_list[-count:]
    newest.reverse()
    if count >= len(key_list):
        has_more = False
    else:
        has_more = True
    return [tx_index.hash for tx_index in newest], has_more


def get_older_sorted_key_list(key_list: 'SortedKeyList[TransactionIndexElement]', timestamp: int,
                              hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
    """ Get sorted key list data from the timestamp/hash_bytes reference to the oldest
        Return the elements (quantity is the 'count' parameter) and a boolean indicating if has more
    """
    # Get idx of element
    idx = key_list.bisect_key_left((timestamp, hash_bytes))
    first_idx = max(0, idx - count)
    txs = key_list[first_idx:idx]
    # Reverse because we want the newest first
    txs.reverse()
    return [tx_index.hash for tx_index in txs], first_idx > 0


def get_newer_sorted_key_list(key_list: 'SortedKeyList[TransactionIndexElement]', timestamp: int,
                              hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
    """ Get sorted key list data from the timestamp/hash_bytes reference to the newest
        Return the elements (quantity is the 'count' parameter) and a boolean indicating if has more
    """
    # Get idx of element
    idx = key_list.bisect_key_left((timestamp, hash_bytes))
    last_idx = min(len(key_list), idx + 1 + count)
    txs = key_list[idx + 1:last_idx]
    # Reverse because we want the newest first
    txs.reverse()
    return [tx_index.hash for tx_index in txs], last_idx < len(key_list)


class TransactionsIndex:
    """ Index of transactions sorted by their timestamps.
    """

    transactions: 'SortedKeyList[TransactionIndexElement]'

    def __init__(self) -> None:
        self.transactions = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def __getitem__(self, index: slice) -> List[TransactionIndexElement]:
        """ Get items from SortedKeyList given a slice

        :param index: list index slice, for eg [1:6]
        """
        return self.transactions[index]

    def update(self, values: List[TransactionIndexElement]) -> None:
        """ Update sorted list by adding all values from iterable

        :param values: new values to add to SortedKeyList
        """
        self.transactions.update(values)

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.hash is not None
        # It is safe to use the in operator because it is O(log(n)).
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.__contains__
        element = TransactionIndexElement(tx.timestamp, tx.hash)
        if element in self.transactions:
            return False
        self.transactions.add(element)
        return True

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Delete a transaction from the index

        :param tx: Transaction to be deleted
        """
        idx = self.transactions.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self.transactions) and self.transactions[idx].hash == tx.hash:
            self.transactions.pop(idx)

    def find_tx_index(self, tx: BaseTransaction) -> Optional[int]:
        """Return the index of a transaction in the index

        :param tx: Transaction to be found
        """
        idx = self.transactions.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self.transactions) and self.transactions[idx].hash == tx.hash:
            return idx
        return None

    def get_newest(self, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the newest to the oldest

        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return get_newest_sorted_key_list(self.transactions, count)

    def get_older(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return get_older_sorted_key_list(self.transactions, timestamp, hash_bytes, count)

    def get_newer(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        return get_newer_sorted_key_list(self.transactions, timestamp, hash_bytes, count)

    def find_first_at_timestamp(self, timestamp: int) -> int:
        """ Get index of first element at the given timestamp, or where it would be inserted if
        the timestamp is not in the list.

        Eg: SortedKeyList = [(3,hash1), (3, hash2), (7, hash3), (8, hash4)]
        find_first_at_timestamp(7) = 2, which is the index of (7, hash3)
        find_first_at_timestamp(4) = 2, which is the index of (7, hash3)

        :param timestamp: timestamp we're interested in
        :return: the index of the element, or None if timestamp is greater than all in the list
        """
        idx = self.transactions.bisect_key_left((timestamp, b''))
        return idx


class WalletIndex:
    """ Index of inputs/outputs by address
    """
    def __init__(self, pubsub: Optional['PubSubManager'] = None) -> None:
        self.index: DefaultDict[str, Set[bytes]] = defaultdict(set)
        self.pubsub = pubsub
        if self.pubsub:
            self.subscribe_pubsub_events()

    def subscribe_pubsub_events(self) -> None:
        """ Subscribe wallet index to receive voided/winner tx pubsub events
        """
        assert self.pubsub is not None
        # Subscribe to voided/winner events
        events = [HathorEvents.STORAGE_TX_VOIDED, HathorEvents.STORAGE_TX_WINNER]
        for event in events:
            self.pubsub.subscribe(event, self.handle_tx_event)

    def _get_addresses(self, tx: BaseTransaction) -> Set[str]:
        """ Return a set of addresses collected from tx's inputs and outputs.
        """
        assert tx.storage is not None
        addresses: Set[str] = set()

        def add_address_from_output(output: 'TxOutput') -> None:
            script_type_out = parse_address_script(output.script)
            if script_type_out:
                address = script_type_out.address
                addresses.add(address)

        for txin in tx.inputs:
            tx2 = tx.storage.get_transaction(txin.tx_id)
            txout = tx2.outputs[txin.index]
            add_address_from_output(txout)

        for txout in tx.outputs:
            add_address_from_output(txout)

        return addresses

    def publish_tx(self, tx: BaseTransaction, *, addresses: Optional[Iterable[str]] = None) -> None:
        """ Publish WALLET_ADDRESS_HISTORY for all addresses of a transaction.
        """
        if not self.pubsub:
            return
        if addresses is None:
            addresses = self._get_addresses(tx)
        data = tx.to_json_extended()
        for address in addresses:
            self.pubsub.publish(HathorEvents.WALLET_ADDRESS_HISTORY, address=address, history=data)

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add tx inputs and outputs to the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = self._get_addresses(tx)
        for address in addresses:
            self.index[address].add(tx.hash)

        self.publish_tx(tx, addresses=addresses)

    def remove_tx(self, tx: BaseTransaction) -> None:
        """ Remove tx inputs and outputs from the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = self._get_addresses(tx)
        for address in addresses:
            self.index[address].discard(tx.hash)

    def handle_tx_event(self, key: HathorEvents, args: 'EventArguments') -> None:
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        tx = data['tx']
        meta = tx.get_metadata()
        if meta.has_voided_by_changed_since_last_call() or meta.has_spent_by_changed_since_last_call():
            self.publish_tx(tx)

    def get_from_address(self, address: str) -> List[bytes]:
        """ Get list of transaction hashes of an address
        """
        return list(self.index[address])

    def get_sorted_from_address(self, address: str) -> List[bytes]:
        """ Get a sorted list of transaction hashes of an address
        """
        return sorted(self.index[address])

    def is_address_empty(self, address: str) -> bool:
        return not bool(self.index[address])


class TokensIndex:
    """ Index of tokens by token uid
    """

    class TokenStatus:
        """ Class used to track token info

        For both sets (mint and melt), the expected tuple is (tx_id, index).

        'total' tracks the amount of tokens in circulation (mint - melt)
        """

        transactions: 'SortedKeyList[TransactionIndexElement]'

        def __init__(self, name: Optional[str] = None, symbol: Optional[str] = None, total: int = 0,
                     mint: Optional[Set[Tuple[bytes, int]]] = None,
                     melt: Optional[Set[Tuple[bytes, int]]] = None) -> None:
            self.name = name
            self.symbol = symbol
            self.total = total
            self.mint = mint or set()
            self.melt = melt or set()
            # Saves the (timestamp, hash) of the transactions that include this token
            self.transactions = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def __init__(self) -> None:
        self.tokens: Dict[bytes, TokensIndex.TokenStatus] = defaultdict(lambda: self.TokenStatus())

    def _add_to_index(self, tx: BaseTransaction, index: int) -> None:
        """ Add tx to mint/melt indexes and total amount
        """
        assert tx.hash is not None

        tx_output = tx.outputs[index]
        token_uid = tx.get_token_uid(tx_output.get_token_index())

        if tx_output.is_token_authority():
            if tx_output.can_mint_token():
                # add to mint index
                self.tokens[token_uid].mint.add((tx.hash, index))
            if tx_output.can_melt_token():
                # add to melt index
                self.tokens[token_uid].melt.add((tx.hash, index))
        else:
            self.tokens[token_uid].total += tx_output.value

    def _remove_from_index(self, tx: BaseTransaction, index: int) -> None:
        """ Remove tx from mint/melt indexes and total amount
        """
        assert tx.hash is not None

        tx_output = tx.outputs[index]
        token_uid = tx.get_token_uid(tx_output.get_token_index())

        if tx_output.is_token_authority():
            if tx_output.can_mint_token():
                # remove from mint index
                self.tokens[token_uid].mint.discard((tx.hash, index))
            if tx_output.can_melt_token():
                # remove from melt index
                self.tokens[token_uid].melt.discard((tx.hash, index))
        else:
            self.tokens[token_uid].total -= tx_output.value

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Checks if this tx has mint or melt inputs/outputs and adds to tokens index
        """
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            self._remove_from_index(spent_tx, tx_input.index)

        for index in range(len(tx.outputs)):
            self._add_to_index(tx, index)

        # if it's a TokenCreationTransaction, update name and symbol
        if tx.version == TxVersion.TOKEN_CREATION_TRANSACTION:
            from hathor.transaction.token_creation_tx import TokenCreationTransaction
            tx = cast(TokenCreationTransaction, tx)
            assert tx.hash is not None
            status = self.tokens[tx.hash]
            status.name = tx.token_name
            status.symbol = tx.token_symbol

        if tx.is_transaction:
            # Adding this tx to the transactions key list
            assert isinstance(tx, Transaction)
            for token_uid in tx.tokens:
                transactions = self.tokens[token_uid].transactions
                # It is safe to use the in operator because it is O(log(n)).
                # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.__contains__
                assert tx.hash is not None
                element = TransactionIndexElement(tx.timestamp, tx.hash)
                if element in transactions:
                    return
                transactions.add(element)

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Tx has been voided, so remove from tokens index (if applicable)
        """
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            self._add_to_index(spent_tx, tx_input.index)

        for index in range(len(tx.outputs)):
            self._remove_from_index(tx, index)

        # if it's a TokenCreationTransaction, remove it from index
        if tx.version == TxVersion.TOKEN_CREATION_TRANSACTION:
            assert tx.hash is not None
            del self.tokens[tx.hash]

        if tx.is_transaction:
            # Removing this tx from the transactions key list
            assert isinstance(tx, Transaction)
            for token_uid in tx.tokens:
                transactions = self.tokens[token_uid].transactions
                idx = transactions.bisect_key_left((tx.timestamp, tx.hash))
                if idx < len(transactions) and transactions[idx].hash == tx.hash:
                    transactions.pop(idx)

    def get_token_info(self, token_uid: bytes) -> 'TokensIndex.TokenStatus':
        """ Get the info from the tokens dict.

        We use a default dict, so querying for unknown token uids will never raise an exception. To overcome that,
        we check the token name and, if it's None, we assume it's an unknown token uid (and raise an exception).

        :raises KeyError: an unknown token uid
        """
        if token_uid not in self.tokens:
            raise KeyError('unknown token')
        info = self.tokens[token_uid]
        return info

    def get_transactions_count(self, token_uid: bytes) -> int:
        """ Get quantity of transactions from requested token
        """
        if token_uid not in self.tokens:
            return 0
        info = self.tokens[token_uid]
        return len(info.transactions)

    def get_newest_transactions(self, token_uid: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions from the newest to the oldest
        """
        if token_uid not in self.tokens:
            return [], False
        transactions = self.tokens[token_uid].transactions
        return get_newest_sorted_key_list(transactions, count)

    def get_older_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> Tuple[List[bytes], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the oldest
        """
        if token_uid not in self.tokens:
            return [], False
        transactions = self.tokens[token_uid].transactions
        return get_older_sorted_key_list(transactions, timestamp, hash_bytes, count)

    def get_newer_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> Tuple[List[bytes], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the newest
        """
        if token_uid not in self.tokens:
            return [], False
        transactions = self.tokens[token_uid].transactions
        return get_newer_sorted_key_list(transactions, timestamp, hash_bytes, count)
