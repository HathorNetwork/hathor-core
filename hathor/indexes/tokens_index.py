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

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterator, NamedTuple, Optional

from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:
    from hathor.nanocontracts.runner.types import UpdateAuthoritiesRecord

SCOPE = Scope(
    include_blocks=False,
    include_txs=True,
    include_voided=True,
)


class TokenUtxoInfo(NamedTuple):
    tx_hash: bytes
    output_index: int


class TokenIndexInfo(ABC):
    """ Class used to track token info

    For both sets (mint and melt), the expected tuple is (tx_id, index).

    'total' tracks the amount of tokens in circulation (mint - melt)
    """

    @abstractmethod
    def get_name(self) -> Optional[str]:
        """The token name"""
        raise NotImplementedError

    @abstractmethod
    def get_symbol(self) -> Optional[str]:
        """The token symbol"""
        raise NotImplementedError

    @abstractmethod
    def get_total(self) -> int:
        """The token's total supply"""
        raise NotImplementedError

    @abstractmethod
    def iter_mint_utxos(self) -> Iterator[TokenUtxoInfo]:
        """Iterate over mint-authority UTXOs"""
        raise NotImplementedError

    @abstractmethod
    def iter_melt_utxos(self) -> Iterator[TokenUtxoInfo]:
        """Iterate over melt-authority UTXOs"""
        raise NotImplementedError

    @abstractmethod
    def can_mint(self) -> bool:
        """Return whether this token can be minted, that is, whether any UTXO or contract holds a mint authority."""
        raise NotImplementedError

    @abstractmethod
    def can_melt(self) -> bool:
        """Return whether this token can be melted, that is, whether any UTXO or contract holds a melt authority."""
        raise NotImplementedError


class TokensIndex(BaseIndex):
    """ Index of tokens by token uid
    """

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        tx_meta = tx.get_metadata()
        if tx_meta.voided_by:
            return
        self.add_tx(tx)

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> None:
        """ Checks if this tx has mint or melt inputs/outputs and adds to tokens index
        """
        raise NotImplementedError

    @abstractmethod
    def remove_tx(self, tx: BaseTransaction) -> None:
        """ Implementation of removal from index called by del_tx.
        """
        raise NotImplementedError

    def del_tx(self, tx: BaseTransaction, *, remove_all: bool = False) -> None:
        """ Tx has been voided, so remove from tokens index (if applicable)
        """
        from hathor.transaction.base_transaction import TxVersion
        if remove_all or tx.version != TxVersion.TOKEN_CREATION_TRANSACTION:
            self.remove_tx(tx)

    @abstractmethod
    def iter_all_tokens(self) -> Iterator[tuple[bytes, TokenIndexInfo]]:
        """ Iterate over all tokens, yields tuples of (token_uid, token_index_info)
        """
        raise NotImplementedError

    @abstractmethod
    def get_token_info(self, token_uid: bytes) -> TokenIndexInfo:
        """ Get the info from the tokens dict.

        We use a default dict, so querying for unknown token uids will never raise an exception. To overcome that,
        we check the token name and, if it's None, we assume it's an unknown token uid (and raise an exception).

        :raises KeyError: an unknown token uid
        """
        raise NotImplementedError

    @abstractmethod
    def create_token_info(
        self,
        token_uid: bytes,
        name: str,
        symbol: str,
        total: int = 0,
        n_contracts_can_mint: int = 0,
        n_contracts_can_melt: int = 0,
    ) -> None:
        """Create a token info for a new token."""
        raise NotImplementedError

    @abstractmethod
    def create_token_info_from_contract(
        self,
        token_uid: bytes,
        name: str,
        symbol: str,
        total: int = 0,
    ) -> None:
        """Create a token info for a new token created in a contract."""
        raise NotImplementedError

    @abstractmethod
    def destroy_token(self, token_uid: bytes) -> None:
        """Destroy a token."""
        raise NotImplementedError

    @abstractmethod
    def update_authorities_from_contract(self, record: UpdateAuthoritiesRecord, undo: bool = False) -> None:
        """
        Handle an UpdateAuthoritiesRecord by incrementing/decrementing the counters of contracts holding authorities.
        """
        raise NotImplementedError

    @abstractmethod
    def get_transactions_count(self, token_uid: bytes) -> int:
        """ Get quantity of transactions from requested token
        """
        raise NotImplementedError

    @abstractmethod
    def get_newest_transactions(self, token_uid: bytes, count: int) -> tuple[list[bytes], bool]:
        """ Get transactions from the newest to the oldest
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> tuple[list[bytes], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the oldest
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> tuple[list[bytes], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the newest
        """
        raise NotImplementedError

    @abstractmethod
    def add_to_total(self, token_uid: bytes, amount: int) -> None:
        """Add an amount to the total of `token_uid`. The amount may be negative."""
        raise NotImplementedError
