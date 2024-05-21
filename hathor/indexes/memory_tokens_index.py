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
from typing import Iterator, Optional, cast

from sortedcontainers import SortedKeyList
from structlog import get_logger
from typing_extensions import assert_never

from hathor.indexes.tokens_index import TokenIndexInfo, TokensIndex, TokenUtxoInfo
from hathor.indexes.utils import (
    TransactionIndexElement,
    get_newer_sorted_key_list,
    get_newest_sorted_key_list,
    get_older_sorted_key_list,
)
from hathor.nanocontracts import NanoContract
from hathor.nanocontracts.types import NCActionType
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.base_transaction import TxVersion
from hathor.util import is_token_uid_valid

logger = get_logger()


class MemoryTokenIndexInfo(TokenIndexInfo):
    _name: Optional[str]
    _symbol: Optional[str]
    _total: int
    _mint: set[TokenUtxoInfo]
    _melt: set[TokenUtxoInfo]
    _transactions: 'SortedKeyList[TransactionIndexElement]'

    def __init__(self, name: Optional[str] = None, symbol: Optional[str] = None, total: int = 0,
                 mint: Optional[set[TokenUtxoInfo]] = None, melt: Optional[set[TokenUtxoInfo]] = None) -> None:
        self._name = name
        self._symbol = symbol
        self._total = total
        self._mint = mint or set()
        self._melt = melt or set()
        # Saves the (timestamp, hash) of the transactions that include this token
        self._transactions = SortedKeyList(key=lambda x: (x.timestamp, x.hash))

    def copy(self) -> 'MemoryTokenIndexInfo':
        copy = MemoryTokenIndexInfo(
            name=self._name,
            symbol=self._symbol,
            total=self._total,
            mint=self._mint,
            melt=self._melt,
        )
        copy._transactions.update(self._transactions)
        return copy

    def get_name(self) -> Optional[str]:
        return self._name

    def get_symbol(self) -> Optional[str]:
        return self._symbol

    def get_total(self) -> int:
        return self._total

    def iter_mint_utxos(self) -> Iterator[TokenUtxoInfo]:
        yield from self._mint

    def iter_melt_utxos(self) -> Iterator[TokenUtxoInfo]:
        yield from self._melt


class MemoryTokensIndex(TokensIndex):
    def __init__(self) -> None:
        self.log = logger.new()
        self.force_clear()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self._tokens: dict[bytes, MemoryTokenIndexInfo] = defaultdict(MemoryTokenIndexInfo)

    def _add_to_index(self, tx: BaseTransaction, index: int) -> None:
        """ Add tx to mint/melt indexes and total amount
        """

        tx_output = tx.outputs[index]
        token_uid = tx.get_token_uid(tx_output.get_token_index())

        if tx_output.is_token_authority():
            if tx_output.can_mint_token():
                # add to mint index
                self._tokens[token_uid]._mint.add(TokenUtxoInfo(tx.hash, index))
            if tx_output.can_melt_token():
                # add to melt index
                self._tokens[token_uid]._melt.add(TokenUtxoInfo(tx.hash, index))
        else:
            self._tokens[token_uid]._total += tx_output.value

    def _remove_from_index(self, tx: BaseTransaction, index: int) -> None:
        """ Remove tx from mint/melt indexes and total amount
        """

        tx_output = tx.outputs[index]
        token_uid = tx.get_token_uid(tx_output.get_token_index())

        if tx_output.is_token_authority():
            if tx_output.can_mint_token():
                # remove from mint index
                self._tokens[token_uid]._mint.discard(TokenUtxoInfo(tx.hash, index))
            if tx_output.can_melt_token():
                # remove from melt index
                self._tokens[token_uid]._melt.discard(TokenUtxoInfo(tx.hash, index))
        else:
            self._tokens[token_uid]._total -= tx_output.value

    def add_tx(self, tx: BaseTransaction) -> None:
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            self._remove_from_index(spent_tx, tx_input.index)

        for index in range(len(tx.outputs)):
            self._add_to_index(tx, index)

        # if it's a TokenCreationTransaction, update name and symbol
        if tx.version == TxVersion.TOKEN_CREATION_TRANSACTION:
            from hathor.transaction.token_creation_tx import TokenCreationTransaction
            tx = cast(TokenCreationTransaction, tx)
            status = self._tokens[tx.hash]
            status._name = tx.token_name
            status._symbol = tx.token_symbol

        # Handle deposits and withdrawals from Nano Contracts.
        if isinstance(tx, NanoContract):
            ctx = tx.get_context()
            for action in ctx.actions.values():
                match action.type:
                    case NCActionType.DEPOSIT:
                        self._tokens[action.token_uid]._total += action.amount
                    case NCActionType.WITHDRAWAL:
                        self._tokens[action.token_uid]._total -= action.amount
                    case _:
                        assert_never(action.type)

        if tx.is_transaction:
            # Adding this tx to the transactions key list
            assert isinstance(tx, Transaction)
            for token_uid in tx.tokens:
                transactions = self._tokens[token_uid]._transactions
                # It is safe to use the in operator because it is O(log(n)).
                # http://www.grantjenks.com/docs/sortedcontainers/sortedlist.html#sortedcontainers.SortedList.__contains__
                element = TransactionIndexElement(tx.timestamp, tx.hash)
                if element in transactions:
                    return
                transactions.add(element)

    def del_tx(self, tx: BaseTransaction) -> None:
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            self._add_to_index(spent_tx, tx_input.index)

        for index in range(len(tx.outputs)):
            self._remove_from_index(tx, index)

        if tx.is_transaction:
            # Removing this tx from the transactions key list
            assert isinstance(tx, Transaction)
            for token_uid in tx.tokens:
                transactions = self._tokens[token_uid]._transactions
                idx = transactions.bisect_key_left((tx.timestamp, tx.hash))
                if idx < len(transactions) and transactions[idx].hash == tx.hash:
                    transactions.pop(idx)

        # if it's a TokenCreationTransaction, remove it from index
        if tx.version == TxVersion.TOKEN_CREATION_TRANSACTION:
            del self._tokens[tx.hash]

    def iter_all_tokens(self) -> Iterator[tuple[bytes, TokenIndexInfo]]:
        yield from self._tokens.items()

    def get_token_info(self, token_uid: bytes) -> TokenIndexInfo:
        assert is_token_uid_valid(token_uid)
        if token_uid not in self._tokens:
            raise KeyError('unknown token')
        info = self._tokens[token_uid]
        return info.copy()

    def get_transactions_count(self, token_uid: bytes) -> int:
        assert is_token_uid_valid(token_uid)
        if token_uid not in self._tokens:
            return 0
        info = self._tokens[token_uid]
        return len(info._transactions)

    def get_newest_transactions(self, token_uid: bytes, count: int) -> tuple[list[bytes], bool]:
        assert is_token_uid_valid(token_uid)
        if token_uid not in self._tokens:
            return [], False
        transactions = self._tokens[token_uid]._transactions
        return get_newest_sorted_key_list(transactions, count)

    def get_older_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> tuple[list[bytes], bool]:
        assert is_token_uid_valid(token_uid)
        if token_uid not in self._tokens:
            return [], False
        transactions = self._tokens[token_uid]._transactions
        return get_older_sorted_key_list(transactions, timestamp, hash_bytes, count)

    def get_newer_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> tuple[list[bytes], bool]:
        assert is_token_uid_valid(token_uid)
        if token_uid not in self._tokens:
            return [], False
        transactions = self._tokens[token_uid]._transactions
        return get_newer_sorted_key_list(transactions, timestamp, hash_bytes, count)
