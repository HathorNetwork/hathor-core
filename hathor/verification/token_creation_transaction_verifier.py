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

from hathor.conf.settings import HathorSettings
from hathor.transaction.exceptions import InvalidToken, TransactionDataError
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfo, TokenVersion
from hathor.transaction.util import validate_token_name_and_symbol
from hathor.types import TokenUid
from hathor.verification.verification_params import VerificationParams


class TokenCreationTransactionVerifier:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings

    def verify_minted_tokens(self, tx: TokenCreationTransaction, token_dict: dict[TokenUid, TokenInfo]) -> None:
        """ Besides all checks made on regular transactions, a few extra ones are made:
        - only HTR tokens on the inputs;
        - new tokens are actually being minted;

        :raises InvalidToken: when there's an error in token operations
        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        # make sure tokens are being minted
        token_info = token_dict[tx.hash]
        if token_info.amount <= 0:
            raise InvalidToken('Token creation transaction must mint new tokens')

    def verify_token_info(self, tx: TokenCreationTransaction, params: VerificationParams) -> None:
        """ Validates token info
        """
        validate_token_name_and_symbol(self._settings, tx.token_name, tx.token_symbol)

        # Can't create the token with NATIVE or a non-activated version
        version_validations = [
            tx.token_version == TokenVersion.NATIVE,
            tx.token_version == TokenVersion.FEE and not params.enable_fee,
        ]

        if any(version_validations):
            raise TransactionDataError('Invalid token version ({})'.format(tx.token_version))
