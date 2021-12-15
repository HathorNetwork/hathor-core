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

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, cast

from sortedcontainers import SortedKeyList
from structlog import get_logger

from hathor.indexes.utils import (
    TransactionIndexElement,
    get_newer_sorted_key_list,
    get_newest_sorted_key_list,
    get_older_sorted_key_list,
)
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.base_transaction import TxVersion

logger = get_logger()


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
