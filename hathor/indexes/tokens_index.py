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

from abc import ABC, abstractmethod
from typing import Iterator, List, NamedTuple, Optional, Tuple

from hathor.transaction import BaseTransaction


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


class TokensIndex(ABC):
    """ Index of tokens by token uid
    """

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> None:
        """ Checks if this tx has mint or melt inputs/outputs and adds to tokens index
        """
        raise NotImplementedError

    @abstractmethod
    def del_tx(self, tx: BaseTransaction) -> None:
        """ Tx has been voided, so remove from tokens index (if applicable)
        """
        raise NotImplementedError

    @abstractmethod
    def iter_all_tokens(self) -> Iterator[Tuple[bytes, TokenIndexInfo]]:
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
    def get_transactions_count(self, token_uid: bytes) -> int:
        """ Get quantity of transactions from requested token
        """
        raise NotImplementedError

    @abstractmethod
    def get_newest_transactions(self, token_uid: bytes, count: int) -> Tuple[List[bytes], bool]:
        """ Get transactions from the newest to the oldest
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> Tuple[List[bytes], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the oldest
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> Tuple[List[bytes], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the newest
        """
        raise NotImplementedError
