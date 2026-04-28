# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.conf.settings import HathorSettings
from hathor.transaction.exceptions import InvalidToken, TransactionDataError
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfo, TokenVersion
from hathor.types import TokenUid
from hathor.verification.verification_params import VerificationParams
from hathorlib.token_amount import SignedAmount
from hathorlib.utils.token_validation import validate_token_name_and_symbol


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
        if token_info.amount <= SignedAmount(0):
            raise InvalidToken('Token creation transaction must mint new tokens')

    def verify_token_info(self, tx: TokenCreationTransaction, params: VerificationParams) -> None:
        """ Validates token info
        """
        validate_token_name_and_symbol(self._settings, tx.token_name, tx.token_symbol)

        # Can't create the token with NATIVE or a non-activated version
        version_validations = [
            tx.token_version == TokenVersion.NATIVE,
            tx.token_version == TokenVersion.FEE and not params.features.fee_tokens,
        ]

        if any(version_validations):
            raise TransactionDataError('Invalid token version ({})'.format(tx.token_version))
