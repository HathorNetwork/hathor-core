# Copyright 2024 Hathor Labs
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

from typing import TYPE_CHECKING

from structlog import get_logger

from hathor.transaction.exceptions import (
    InvalidShieldedOutputError,
    ShieldedAuthorityError,
    ShieldedMintMeltForbiddenError,
    TrivialCommitmentError,
)
from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput
from hathor.transaction.token_info import TokenInfoDict, TokenVersion

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction.transaction import Transaction


_CRYPTO_TOKEN_UID_SIZE = 32


def _normalize_token_uid(token_uid: bytes) -> bytes:
    """Normalize a token UID to 32 bytes for the crypto library.

    Hathor uses b'\\x00' (1 byte) for HTR and 32-byte hashes for custom tokens.
    The crypto library always expects 32-byte token UIDs.
    """
    if len(token_uid) == _CRYPTO_TOKEN_UID_SIZE:
        return token_uid
    if len(token_uid) == 1:
        return token_uid.ljust(_CRYPTO_TOKEN_UID_SIZE, b'\x00')
    raise InvalidShieldedOutputError(
        f'invalid token UID length: expected 1 or {_CRYPTO_TOKEN_UID_SIZE} bytes, got {len(token_uid)}'
    )


logger = get_logger()


class ShieldedTransactionVerifier:
    __slots__ = ('_settings', 'log')

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings
        self.log = logger.new()

    @staticmethod
    def calculate_shielded_fee(settings: HathorSettings, tx: Transaction) -> int:
        """Calculate the total fee required for shielded outputs."""
        fee = 0
        for output in tx.shielded_outputs:
            if isinstance(output, AmountShieldedOutput):
                fee += settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT
            elif isinstance(output, FullShieldedOutput):
                fee += settings.FEE_PER_FULL_SHIELDED_OUTPUT
        return fee

    def verify_shielded_fee(self, tx: Transaction) -> None:
        """Verify the transaction declares sufficient fees for its shielded outputs."""
        if not tx.has_fees():
            raise InvalidShieldedOutputError('shielded transactions require a fee header')
        fee_header = tx.get_fee_header()
        expected_shielded_fee = self.calculate_shielded_fee(self._settings, tx)
        total_declared_fee = fee_header.total_fee_amount()
        if total_declared_fee < expected_shielded_fee:
            raise InvalidShieldedOutputError(
                f'insufficient fee for shielded outputs: declared {total_declared_fee}, '
                f'minimum shielded fee is {expected_shielded_fee}'
            )

    def verify_no_mint_melt(self, token_dict: TokenInfoDict) -> None:
        """Reject mint/melt operations in transactions with shielded outputs.

        The homomorphic balance equation enforces conservation (inputs = outputs).
        Minting/melting breaks this equation. Additionally, the deposit calculation
        in verify_token_rules only tracks transparent flows, so it would be incorrect
        for shielded minting.

        Authority pass-through (amount=0 with can_mint/can_melt) is still allowed.
        """
        for token_uid, token_info in token_dict.items():
            if token_info.version == TokenVersion.NATIVE:
                continue
            if token_info.can_mint and token_info.has_been_minted():
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: minting is not allowed in transactions '
                    f'with shielded outputs (transparent surplus: {token_info.amount})'
                )
            if token_info.can_melt and token_info.has_been_melted():
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: melting is not allowed in transactions '
                    f'with shielded outputs (transparent deficit: {token_info.amount})'
                )

    def verify_shielded_outputs(self, tx: Transaction) -> None:
        """Top-level: calls all checks."""
        self.verify_commitments_valid(tx)
        self.verify_authority_restriction(tx)  # VULN-004: must run before range_proofs
        self.verify_range_proofs(tx)
        self.verify_trivial_commitment_protection(tx)
        self.verify_shielded_fee(tx)

    def verify_shielded_outputs_with_storage(self, tx: Transaction) -> None:
        """Shielded verifications that need storage (balance, surjection, trivial commitment)."""
        self.verify_surjection_proofs(tx)
        self.verify_shielded_balance(tx)
        self._verify_trivial_commitment_with_storage(tx)

    def _verify_trivial_commitment_with_storage(self, tx: Transaction) -> None:
        """VULN-008: Storage-aware trivial commitment protection.

        If all inputs are transparent, require >= 2 shielded outputs.
        If any input is shielded, allow 1 shielded output.
        """
        if not tx.shielded_outputs:
            return
        if self._has_shielded_input(tx):
            return  # Relaxed: shielded inputs already provide mixing
        if len(tx.shielded_outputs) < 2:
            raise TrivialCommitmentError(
                'when all inputs are transparent, at least 2 shielded outputs are required '
                f'to prevent trivial commitment matching (got {len(tx.shielded_outputs)})'
            )

    def verify_commitments_valid(self, tx: Transaction) -> None:
        """Validate all commitments are exactly 33 bytes, valid curve points, and count is within limits."""
        # TODO: Verify output count <= MAX_SHIELDED_OUTPUTS. For each shielded output, check
        # commitment size == COMMITMENT_SIZE (33B) and call validate_commitment() from
        # hathor.crypto.shielded to ensure it's a valid secp256k1 curve point (VULN-007).
        # For FullShieldedOutput, also check asset_commitment size == ASSET_COMMITMENT_SIZE
        # and call validate_generator(). Validate ephemeral_pubkey size and curve point validity.
        pass

    def verify_range_proofs(self, tx: Transaction) -> None:
        """Rule 5: Every shielded output must have valid Bulletproof range proof."""
        # TODO: For each shielded output, derive the generator: for AmountShieldedOutput use
        # derive_asset_tag(token_uid) from hathor.crypto.shielded; for FullShieldedOutput use
        # output.asset_commitment. Then call verify_range_proof(proof, commitment, generator)
        # to validate the Bulletproof range proof (proves amount in [0, 2^64)).
        pass

    def verify_surjection_proofs(self, tx: Transaction) -> None:
        """Rule 6: Only FullShieldedOutput instances require surjection proofs."""
        # TODO: Build domain of input asset generators: for transparent inputs use
        # derive_asset_tag(token_uid), for shielded inputs use asset_commitment (FullShielded)
        # or derive_asset_tag (AmountShielded). Then for each FullShieldedOutput, call
        # verify_surjection_proof(proof, asset_commitment, domain_generators) from
        # hathor.crypto.shielded to prove the output's token type is one of the inputs.
        pass

    def verify_shielded_balance(self, tx: Transaction) -> None:
        """Homomorphic balance verification.

        sum(C_in) == sum(C_out) + fee*H_HTR

        Transparent inputs/outputs are converted to trivial commitments.
        """
        # TODO: Collect transparent inputs/outputs as (value, token_uid) pairs and shielded
        # inputs/outputs as commitment bytes. Append fee entries as transparent outputs.
        # Call verify_balance(transparent_inputs, shielded_inputs, transparent_outputs,
        # shielded_outputs) from hathor.crypto.shielded to check the homomorphic balance
        # equation: sum(C_in) == sum(C_out) + fee*H_HTR.
        pass

    def verify_authority_restriction(self, tx: Transaction) -> None:
        """Rule 7: Shielded outputs cannot be authority (mint/melt) outputs."""
        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, AmountShieldedOutput):
                # Check if token_data has authority bits set
                from hathor.transaction import TxOutput
                if output.token_data & TxOutput.TOKEN_AUTHORITY_MASK:
                    raise ShieldedAuthorityError(
                        f'shielded output {i}: authority outputs cannot be shielded'
                    )

    def verify_trivial_commitment_protection(self, tx: Transaction) -> None:
        """Rule 4: Without storage, conservatively require >= 2 shielded outputs always.

        VULN-008: The storage-less version cannot determine if inputs are shielded,
        so it conservatively requires >= 2 shielded outputs in all cases.
        The storage-aware version (_has_shielded_input) can relax this.
        """
        if not tx.shielded_outputs:
            return

        if len(tx.shielded_outputs) < 2:
            raise TrivialCommitmentError(
                'at least 2 shielded outputs are required '
                f'to prevent trivial commitment matching (got {len(tx.shielded_outputs)})'
            )

    def _has_shielded_input(self, tx: Transaction) -> bool:
        """Check if any input references a shielded output (requires storage)."""
        assert tx.storage is not None
        for tx_input in tx.inputs:
            spent_tx = tx.storage.get_transaction(tx_input.tx_id)
            if tx_input.index >= len(spent_tx.outputs):
                # Index beyond transparent outputs → references shielded output
                return True
        return False
