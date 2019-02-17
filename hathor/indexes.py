from abc import ABC
from collections import defaultdict
from math import inf
from typing import TYPE_CHECKING, DefaultDict, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

from intervaltree import Interval, IntervalTree
from sortedcontainers import SortedKeyList
from twisted.logger import Logger

from hathor.pubsub import HathorEvents
from hathor.transaction import BaseTransaction
from hathor.transaction.scripts import parse_address_script

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import PubSubManager, EventArguments  # noqa: F401


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

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add a transaction to the indexes

        :param tx: Transaction to be added
        """
        self.tips_index.add_tx(tx)
        self.txs_index.add_tx(tx)

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        """
        self.tips_index.del_tx(tx)
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

    log = Logger()

    # An interval tree used to know the tips at any timestamp.
    # The intervals are in the form (begin, end), where begin is the timestamp
    # of the transaction, and end is the smallest timestamp of the tx's children.
    tree: IntervalTree

    # It is a way to access the interval by the hash of the transaction.
    # It is useful because the interval tree allows access only by the interval.
    tx_last_interval: Dict[bytes, Interval]

    def __init__(self) -> None:
        self.tree = IntervalTree()
        self.tx_last_interval = {}  # Dict[bytes(hash), Interval]

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add a new transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.hash is not None
        assert tx.storage is not None
        if tx.hash in self.tx_last_interval:
            return

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

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Remove a transaction from the index.
        """
        assert tx.hash is not None
        assert tx.storage is not None

        interval = self.tx_last_interval.pop(tx.hash, None)
        if interval is None:
            return
        assert interval.end == inf
        self.tree.remove(interval)

        # Update its parents as tips if needed.
        # FIXME Although it works, it does not seem to be a good solution.
        for parent_hash in tx.parents:
            parent = tx.storage.get_transaction(parent_hash)
            if parent.is_block != tx.is_block:
                continue
            self.update_tx(parent)

    def update_tx(self, tx: BaseTransaction) -> None:
        """ Update a tx according to its children.
        """
        assert tx.storage is not None
        assert tx.hash is not None

        meta = tx.get_metadata()
        if meta.voided_by:
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


class TransactionsIndex:
    """ Index of transactions sorted by their timestamps.
    """

    transactions: 'SortedKeyList[TransactionIndexElement]'

    def __init__(self) -> None:
        self.transactions = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add a transaction to the index

        :param tx: Transaction to be added
        """
        assert tx.hash is not None
        # It is safe to use the in operator because it is O(log(n)).
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.__contains__
        if tx in self.transactions:
            return
        self.transactions.add(TransactionIndexElement(tx.timestamp, tx.hash))

    def del_tx(self, tx: BaseTransaction) -> None:
        """ Delete a transaction from the index

        :param tx: Transaction to be deleted
        """
        idx = self.transactions.bisect_key_left((tx.timestamp, tx.hash))
        if idx < len(self.transactions) and self.transactions[idx].hash == tx.hash:
            self.transactions.pop(idx)

    def get_newest(self, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the newest to the oldest

        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        newest = self.transactions[-count:]
        newest.reverse()
        if count >= len(self.transactions):
            has_more = False
        else:
            has_more = True
        return [tx_index.hash for tx_index in newest], has_more

    def get_older(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        # Get idx of element
        idx = self.transactions.bisect_key_left((timestamp, hash_bytes))
        first_idx = max(0, idx - count)
        txs = self.transactions[first_idx:idx]
        # Reverse because we want the newest first
        txs.reverse()
        return [tx_index.hash for tx_index in txs], first_idx > 0

    def get_newer(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        # Get idx of element
        idx = self.transactions.bisect_key_left((timestamp, hash_bytes))
        last_idx = min(len(self.transactions), idx + 1 + count)
        txs = self.transactions[idx + 1:last_idx]
        # Reverse because we want the newest first
        txs.reverse()
        return [tx_index.hash for tx_index in txs], last_idx < len(self.transactions)


class WalletIndex:
    """ Index of inputs/outputs by address
    """
    def __init__(self, pubsub: Optional['PubSubManager'] = None) -> None:
        self.index: DefaultDict[str, List['WalletIndexElement']] = defaultdict(list)

        # Pubsub to send events
        self.pubsub = pubsub
        if self.pubsub:
            self.subscribe_pubsub_events()

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add tx inputs and outputs to the wallet index (indexed by address)
        """
        meta = tx.get_metadata()
        voided = len(meta.voided_by) != 0
        for element in WalletIndex.tx_to_elements(tx, voided):
            address = element.address
            wallet_element = element.element
            self.index[address].append(wallet_element)
            self.publish_update(address, wallet_element)

    @classmethod
    def tx_to_elements(cls, tx: BaseTransaction, voided: bool) -> Iterator['WalletIndexElementAddress']:
        """ Transform tx in wallet elements
        """
        for index, output in enumerate(tx.outputs):
            script_type_out = parse_address_script(output.script)
            if script_type_out:
                address = script_type_out.address
                token_index = output.get_token_index()
                token_uid = tx.get_token_uid(token_index)
                wallet_output = WalletIndexOutput(
                    tx_id=tx.hash_hex,
                    index=index,
                    value=output.value,
                    timestamp=tx.timestamp,
                    token_uid=token_uid.hex(),
                    voided=voided,
                    timelock=script_type_out.timelock
                )
                yield WalletIndexElementAddress(address=address, element=wallet_output)

        for _input in tx.inputs:
            assert tx.storage is not None
            output_tx = tx.storage.get_transaction(_input.tx_id)
            output = output_tx.outputs[_input.index]
            token_index = output.get_token_index()
            token_uid = output_tx.get_token_uid(token_index)

            script_type_out = parse_address_script(output.script)
            if script_type_out:
                address = script_type_out.address
                wallet_input = WalletIndexInput(
                    tx_id=tx.hash_hex,
                    index=_input.index,
                    value=output.value,
                    timestamp=tx.timestamp,
                    token_uid=token_uid.hex(),
                    timelock=script_type_out.timelock,
                    voided=voided,
                    from_tx_id=_input.tx_id.hex()
                )
                yield WalletIndexElementAddress(address=address, element=wallet_input)

    def update_voided_data(self, tx: BaseTransaction, voided: bool) -> None:
        """ Set wallet index elements as voided/not voided for the tx in the parameter
        """
        for index, output in enumerate(tx.outputs):
            script_type_out = parse_address_script(output.script)
            if script_type_out:
                address = script_type_out.address
                token_index = output.get_token_index()
                token_uid = tx.get_token_uid(token_index).hex()
                for wallet_output in self.index[address]:
                    if (wallet_output.tx_id == tx.hash_hex and wallet_output.index == index and
                            wallet_output.is_output):
                        assert wallet_output.token_uid == token_uid
                        wallet_output.voided = voided

        for _input in tx.inputs:
            assert tx.storage is not None
            output_tx = tx.storage.get_transaction(_input.tx_id)
            output = output_tx.outputs[_input.index]
            token_index = output.get_token_index()
            token_uid = output_tx.get_token_uid(token_index).hex()

            script_type_out = parse_address_script(output.script)
            if script_type_out:
                address = script_type_out.address
                for wallet_input in self.index[address]:
                    if (isinstance(wallet_input, WalletIndexInput)):
                        if (wallet_input.tx_id == tx.hash_hex and wallet_input.index == _input.index and
                                wallet_input.from_tx_id == _input.tx_id.hex()):
                            assert wallet_input.token_uid == token_uid
                            wallet_input.voided = voided

    def publish_update(self, address: str, element: 'WalletIndexElement') -> None:
        """ Publish the new wallet element in the index to pubsub
        """
        if self.pubsub:
            self.pubsub.publish(HathorEvents.WALLET_ADDRESS_HISTORY, address=address, history=element)

    def get_from_address(self, address: str) -> List['WalletIndexElement']:
        """ Get inputs/outputs history from address
        """
        return self.index[address]

    def subscribe_pubsub_events(self):
        """ Subscribe wallet index to receive voided/winner tx pubsub events
        """
        # Subscribe to voided/winner events
        events = [HathorEvents.STORAGE_TX_VOIDED, HathorEvents.STORAGE_TX_WINNER]
        for event in events:
            self.pubsub.subscribe(event, self.handle_tx_event)

    def handle_tx_event(self, key: HathorEvents, args: 'EventArguments'):
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        tx = data['tx']
        voided = key == HathorEvents.STORAGE_TX_VOIDED
        self.update_voided_data(tx, voided)


class WalletIndexElement(ABC):
    def __init__(self, tx_id: str, value: int, timestamp: int, index: int, token_uid: str,
                 voided: bool, timelock: Optional[int] = None, is_output: bool = True) -> None:
        self.tx_id = tx_id
        self.value = value
        self.timestamp = timestamp
        self.index = index
        self.token_uid = token_uid
        self.is_output = is_output
        self.voided = voided
        self.timelock = timelock


class WalletIndexOutput(WalletIndexElement):
    def __init__(self, tx_id: str, value: int, timestamp: int, index: int, token_uid: str,
                 timelock: Optional[int], voided: bool) -> None:
        super().__init__(
            tx_id=tx_id,
            value=value,
            timestamp=timestamp,
            index=index,
            token_uid=token_uid,
            timelock=timelock,
            voided=voided,
            is_output=True
        )


class WalletIndexInput(WalletIndexElement):
    def __init__(self, tx_id: str, value: int, timestamp: int, index: int, token_uid: str,
                 timelock: Optional[int], voided: bool, from_tx_id: str) -> None:
        super().__init__(
            tx_id=tx_id,
            value=value,
            timestamp=timestamp,
            index=index,
            token_uid=token_uid,
            timelock=timelock,
            voided=voided,
            is_output=False
        )
        self.from_tx_id = from_tx_id


class WalletIndexElementAddress(NamedTuple):
    address: str
    element: 'WalletIndexElement'
