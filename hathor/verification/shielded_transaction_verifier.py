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

from hathor.crypto.shielded import (
    derive_asset_tag,
    validate_commitment,
    validate_generator,
    verify_balance,
    verify_range_proof,
    verify_surjection_proof,
)
from hathor.transaction.exceptions import (
    InvalidRangeProofError,
    InvalidShieldedOutputError,
    InvalidSurjectionProofError,
    ShieldedAuthorityError,
    ShieldedBalanceMismatchError,
    ShieldedMintMeltForbiddenError,
    TrivialCommitmentError,
)
from hathor.transaction.shielded_tx_output import (
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    MAX_SHIELDED_OUTPUTS,
    AmountShieldedOutput,
    FullShieldedOutput,
)
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
        if len(tx.shielded_outputs) > MAX_SHIELDED_OUTPUTS:
            raise InvalidShieldedOutputError(
                f'too many shielded outputs: {len(tx.shielded_outputs)} exceeds maximum {MAX_SHIELDED_OUTPUTS}'
            )
        for i, output in enumerate(tx.shielded_outputs):
            if len(output.commitment) != COMMITMENT_SIZE:
                raise InvalidShieldedOutputError(
                    f'shielded output {i}: commitment must be {COMMITMENT_SIZE} bytes, '
                    f'got {len(output.commitment)}'
                )
            # VULN-007: Validate that commitments are actual valid curve points
            if not validate_commitment(output.commitment):
                raise InvalidShieldedOutputError(
                    f'shielded output {i}: invalid commitment (not a valid curve point)'
                )
            if isinstance(output, FullShieldedOutput):
                if len(output.asset_commitment) != ASSET_COMMITMENT_SIZE:
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: asset_commitment must be {ASSET_COMMITMENT_SIZE} bytes, '
                        f'got {len(output.asset_commitment)}'
                    )
                if not validate_generator(output.asset_commitment):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: invalid asset_commitment (not a valid curve point)'
                    )

            # Validate ephemeral pubkey if present
            if output.ephemeral_pubkey:
                if len(output.ephemeral_pubkey) != EPHEMERAL_PUBKEY_SIZE:
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: ephemeral_pubkey must be {EPHEMERAL_PUBKEY_SIZE} bytes, '
                        f'got {len(output.ephemeral_pubkey)}'
                    )
                try:
                    from hathor.crypto.util import get_public_key_from_bytes_compressed
                    get_public_key_from_bytes_compressed(output.ephemeral_pubkey)
                except (ValueError, TypeError):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: invalid ephemeral_pubkey (not a valid secp256k1 point)'
                    )

    def verify_range_proofs(self, tx: Transaction) -> None:
        """Rule 5: Every shielded output must have valid Bulletproof range proof."""
        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, AmountShieldedOutput):
                # Generator is the trivial (unblinded) asset tag for the token
                # Bounds-check token_data before accessing the token list
                token_index = output.token_data & 0x7F  # mask out authority bits
                if token_index > len(tx.tokens):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: token_data index {token_index} '
                        f'exceeds token list length {len(tx.tokens)}'
                    )
                token_uid = _normalize_token_uid(tx.get_token_uid(token_index))
                generator = derive_asset_tag(token_uid)
            elif isinstance(output, FullShieldedOutput):
                # Generator is the blinded asset commitment
                generator = output.asset_commitment
            else:
                raise InvalidShieldedOutputError(f'shielded output {i}: unknown type')

            try:
                if not verify_range_proof(output.range_proof, output.commitment, generator):
                    raise InvalidRangeProofError(
                        f'shielded output {i}: range proof verification failed'
                    )
            except ValueError as e:
                raise InvalidRangeProofError(f'shielded output {i}: {e}') from e

    def verify_surjection_proofs(self, tx: Transaction) -> None:
        """Rule 6: Only FullShieldedOutput instances require surjection proofs."""
        assert tx.storage is not None
        # Build domain: all input asset commitments/tags
        domain_generators: list[bytes] = []
        for tx_input in tx.inputs:
            spent_tx = tx.storage.get_transaction(tx_input.tx_id)
            spent_index = tx_input.index
            # Check if the spent output is a standard output
            if spent_index < len(spent_tx.outputs):
                # Transparent input: use trivial asset tag
                spent_output = spent_tx.outputs[spent_index]
                token_uid = _normalize_token_uid(spent_tx.get_token_uid(spent_output.get_token_index()))
                domain_generators.append(derive_asset_tag(token_uid))
            else:
                # Shielded input: use the stored asset commitment
                shielded_index = spent_index - len(spent_tx.outputs)
                if shielded_index >= len(spent_tx.shielded_outputs):
                    raise InvalidShieldedOutputError(
                        f'input references non-existent shielded output index {spent_index}'
                    )
                shielded_out = spent_tx.shielded_outputs[shielded_index]
                if isinstance(shielded_out, FullShieldedOutput):
                    domain_generators.append(shielded_out.asset_commitment)
                elif isinstance(shielded_out, AmountShieldedOutput):
                    # CONS-016: Mask authority bits to get the token index
                    token_uid = _normalize_token_uid(spent_tx.get_token_uid(shielded_out.token_data & 0x7F))
                    domain_generators.append(derive_asset_tag(token_uid))

        # Check that FullShieldedOutputs have a non-empty domain to prove against
        has_full_shielded = any(isinstance(o, FullShieldedOutput) for o in tx.shielded_outputs)
        if has_full_shielded and not domain_generators:
            raise InvalidSurjectionProofError(
                'FullShieldedOutput requires at least one input to form a surjection proof domain'
            )

        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, FullShieldedOutput):
                if not output.surjection_proof:
                    raise InvalidSurjectionProofError(
                        f'shielded output {i}: FullShieldedOutput requires surjection proof'
                    )
                try:
                    if not verify_surjection_proof(
                        output.surjection_proof,
                        output.asset_commitment,
                        domain_generators,
                    ):
                        raise InvalidSurjectionProofError(
                            f'shielded output {i}: surjection proof verification failed'
                        )
                except ValueError as e:
                    raise InvalidSurjectionProofError(f'shielded output {i}: {e}') from e

    def verify_shielded_balance(self, tx: Transaction) -> None:
        """Homomorphic balance verification.

        sum(C_in) == sum(C_out) + fee*H_HTR

        Transparent inputs/outputs are converted to trivial commitments.
        """
        assert tx.storage is not None
        transparent_inputs: list[tuple[int, bytes]] = []
        shielded_inputs: list[bytes] = []

        for tx_input in tx.inputs:
            spent_tx = tx.storage.get_transaction(tx_input.tx_id)
            spent_index = tx_input.index
            if spent_index < len(spent_tx.outputs):
                # Transparent input
                spent_output = spent_tx.outputs[spent_index]
                if not spent_output.is_token_authority():
                    token_uid = _normalize_token_uid(spent_tx.get_token_uid(spent_output.get_token_index()))
                    transparent_inputs.append((spent_output.value, token_uid))
            else:
                # Shielded input
                shielded_index = spent_index - len(spent_tx.outputs)
                if shielded_index >= len(spent_tx.shielded_outputs):
                    raise InvalidShieldedOutputError(
                        f'input references non-existent shielded output index {spent_index}'
                    )
                shielded_out = spent_tx.shielded_outputs[shielded_index]
                shielded_inputs.append(shielded_out.commitment)

        transparent_outputs: list[tuple[int, bytes]] = []
        shielded_outputs: list[bytes] = []

        for output in tx.outputs:
            if output.is_token_authority():
                continue
            token_uid = _normalize_token_uid(tx.get_token_uid(output.get_token_index()))
            transparent_outputs.append((output.value, token_uid))

        for shielded_output in tx.shielded_outputs:
            shielded_outputs.append(shielded_output.commitment)

        # Append fee entries as transparent outputs (VULN-012 fee check is in verify_shielded_fee)
        if tx.has_fees():
            for fee_entry in tx.get_fee_header().get_fees():
                token_uid = _normalize_token_uid(fee_entry.token_uid)
                transparent_outputs.append((fee_entry.amount, token_uid))

        try:
            if not verify_balance(
                transparent_inputs,
                shielded_inputs,
                transparent_outputs,
                shielded_outputs,
            ):
                raise ShieldedBalanceMismatchError(
                    'shielded balance equation does not hold'
                )
        except ValueError as e:
            raise ShieldedBalanceMismatchError(f'balance verification error: {e}') from e

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
