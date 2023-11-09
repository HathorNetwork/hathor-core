#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.transaction import Transaction
from hathor.transaction.exceptions import InvalidToken, TransactionDataError
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.util import clean_token_string
from hathor.util import not_none
from hathor.verification.transaction_verifier import TransactionVerifier


class TokenCreationTransactionVerifier(TransactionVerifier):
    __slots__ = ()

    def verify(self, tx: TokenCreationTransaction, *, reject_locked_reward: bool = True) -> None:
        """ Run all validations as regular transactions plus validation on token info.

        We also overload verify_sum to make some different checks
        """
        super().verify(tx, reject_locked_reward=reject_locked_reward)
        self.verify_token_info(tx)

    def verify_sum(self, tx: Transaction) -> None:
        """ Besides all checks made on regular transactions, a few extra ones are made:
        - only HTR tokens on the inputs;
        - new tokens are actually being minted;

        :raises InvalidToken: when there's an error in token operations
        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        assert isinstance(tx, TokenCreationTransaction)
        token_dict = tx.get_complete_token_info()

        # make sure tokens are being minted
        token_info = token_dict[not_none(tx.hash)]
        if token_info.amount <= 0:
            raise InvalidToken('Token creation transaction must mint new tokens')

        super().verify_sum(tx)

    def verify_token_info(self, tx: TokenCreationTransaction) -> None:
        """ Validates token info
        """
        name_len = len(tx.token_name)
        symbol_len = len(tx.token_symbol)
        if name_len == 0 or name_len > self._settings.MAX_LENGTH_TOKEN_NAME:
            raise TransactionDataError('Invalid token name length ({})'.format(name_len))
        if symbol_len == 0 or symbol_len > self._settings.MAX_LENGTH_TOKEN_SYMBOL:
            raise TransactionDataError('Invalid token symbol length ({})'.format(symbol_len))

        # Can't create token with hathor name or symbol
        if clean_token_string(tx.token_name) == clean_token_string(self._settings.HATHOR_TOKEN_NAME):
            raise TransactionDataError('Invalid token name ({})'.format(tx.token_name))
        if clean_token_string(tx.token_symbol) == clean_token_string(self._settings.HATHOR_TOKEN_SYMBOL):
            raise TransactionDataError('Invalid token symbol ({})'.format(tx.token_symbol))
