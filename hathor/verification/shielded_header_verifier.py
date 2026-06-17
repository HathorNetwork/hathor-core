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

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import (
    InvalidRangeProofError,
    InvalidShieldedOutputError,
    InvalidSurjectionProofError,
    ShieldedAuthorityError,
    ShieldedBalanceMismatchError,
    ShieldedMintMeltForbiddenError,
    TrivialCommitmentError,
)
from hathor.transaction.token_info import TokenInfoDict, TokenVersion

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings


class ShieldedHeaderVerifier:
    __slots__ = ('_settings',)

    def __init__(
        self,
        *,
        settings: HathorSettings,
    ) -> None:
        self._settings = settings

    @staticmethod
    def _normalize_token_uid(token_uid: bytes) -> bytes:
        """Normalize a token UID to 32 bytes for the crypto library."""
        from hathor.crypto.shielded.asset_tag import normalize_token_uid
        try:
            return normalize_token_uid(token_uid)
        except ValueError as e:
            raise InvalidShieldedOutputError(str(e)) from e

    @staticmethod
    def calculate_shielded_fee(settings: HathorSettings, tx: Transaction) -> int:
        """Calculate the total fee required for shielded outputs."""
        from hathorlib.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput
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

    def verify_shielded_outputs(self, tx: Transaction) -> None:
        """Top-level: calls all basic shielded checks."""
        self.verify_commitments_valid(tx)
        self.verify_authority_restriction(tx)
        self.verify_range_proofs(tx)
        self.verify_trivial_commitment_protection(tx)
        self.verify_shielded_fee(tx)

    def verify_shielded_outputs_with_storage(self, tx: Transaction) -> None:
        """Outputs-only shielded checks that need storage (surjection proofs).

        Gated on has_shielded_outputs() — surjection proves each shielded output's
        asset came from some input, so it only runs when there are shielded outputs.

        Whole-tx balance (verify_shielded_balance) is NOT called here — it's
        dispatched from _verify_tx as the counterpart to verify_transparent_balance,
        so every tx gets exactly one balance check regardless of shape.
        """
        assert tx.storage is not None

        spent_txs: dict[bytes, BaseTransaction] = {}
        for tx_input in tx.inputs:
            if tx_input.tx_id not in spent_txs:
                spent_txs[tx_input.tx_id] = tx.storage.get_transaction(tx_input.tx_id)

        asset_tag_cache: dict[bytes, bytes] = {}

        self.verify_surjection_proofs(tx, spent_txs=spent_txs, asset_tag_cache=asset_tag_cache)

    def verify_commitments_valid(self, tx: Transaction) -> None:
        """Validate all commitments are exactly 33 bytes, valid curve points, and count is within limits."""
        from hathor_ct_crypto import validate_commitment, validate_generator

        from hathor.crypto.util import get_public_key_from_bytes_compressed
        from hathorlib.transaction.shielded_tx_output import (
            ASSET_COMMITMENT_SIZE,
            COMMITMENT_SIZE,
            EPHEMERAL_PUBKEY_SIZE,
            MAX_SHIELDED_OUTPUTS,
            FullShieldedOutput,
        )

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

            if output.ephemeral_pubkey:
                if len(output.ephemeral_pubkey) != EPHEMERAL_PUBKEY_SIZE:
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: ephemeral_pubkey must be {EPHEMERAL_PUBKEY_SIZE} bytes, '
                        f'got {len(output.ephemeral_pubkey)}'
                    )
                try:
                    get_public_key_from_bytes_compressed(output.ephemeral_pubkey)
                except (ValueError, TypeError):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: invalid ephemeral_pubkey (not a valid secp256k1 point)'
                    )

    def verify_range_proofs(self, tx: Transaction) -> None:
        """Every shielded output must have valid Borromean range proof."""
        from hathor_ct_crypto import verify_range_proof

        from hathorlib.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput

        asset_tag_cache: dict[bytes, bytes] = {}
        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, AmountShieldedOutput):
                token_index = output.token_data & 0x7F
                if token_index > len(tx.tokens):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: token_data index {token_index} '
                        f'exceeds token list length {len(tx.tokens)}'
                    )
                token_uid = tx.get_token_uid(token_index)
                generator = self._get_or_derive_asset_tag(token_uid, asset_tag_cache)
            elif isinstance(output, FullShieldedOutput):
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

    def _get_or_derive_asset_tag(
        self,
        token_uid: bytes,
        asset_tag_cache: dict[bytes, bytes] | None,
    ) -> bytes:
        """Derive an asset tag, using the cache if available."""
        from hathor_ct_crypto import derive_asset_tag
        normalized = self._normalize_token_uid(token_uid)
        if asset_tag_cache is not None:
            if normalized not in asset_tag_cache:
                asset_tag_cache[normalized] = derive_asset_tag(normalized)
            return asset_tag_cache[normalized]
        return derive_asset_tag(normalized)

    def verify_surjection_proofs(
        self,
        tx: Transaction,
        *,
        spent_txs: dict[bytes, BaseTransaction] | None = None,
        asset_tag_cache: dict[bytes, bytes] | None = None,
    ) -> None:
        """Only FullShieldedOutput instances require surjection proofs.

        Builds the surjection-proof domain from the asset generators of the
        transparent and shielded inputs; each FullShieldedOutput must prove its
        asset is one of them.
        """
        from hathor_ct_crypto import verify_surjection_proof

        from hathorlib.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput

        assert tx.storage is not None
        domain_generators: list[bytes] = []
        for tx_input in tx.inputs:
            spent_tx = spent_txs[tx_input.tx_id] if spent_txs else tx.storage.get_transaction(tx_input.tx_id)
            spent_index = tx_input.index
            if spent_index < len(spent_tx.outputs):
                spent_output = spent_tx.outputs[spent_index]
                if spent_output.is_token_authority():
                    continue
                token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
                domain_generators.append(self._get_or_derive_asset_tag(token_uid, asset_tag_cache))
            else:
                shielded_index = spent_index - len(spent_tx.outputs)
                if shielded_index >= len(spent_tx.shielded_outputs):
                    raise InvalidShieldedOutputError(
                        f'input references non-existent shielded output index {spent_index}'
                    )
                shielded_out = spent_tx.shielded_outputs[shielded_index]
                if isinstance(shielded_out, FullShieldedOutput):
                    domain_generators.append(shielded_out.asset_commitment)
                elif isinstance(shielded_out, AmountShieldedOutput):
                    token_index = shielded_out.token_data & 0x7F
                    try:
                        token_uid = spent_tx.get_token_uid(token_index)
                    except (IndexError, NotImplementedError) as e:
                        raise InvalidShieldedOutputError(
                            f'spent shielded output token_data index {token_index} '
                            f'is invalid for the spent transaction'
                        ) from e
                    domain_generators.append(self._get_or_derive_asset_tag(token_uid, asset_tag_cache))

        # TODO (mint/melt — postponed): the mint/melt extension extends the surjection-proof
        # domain with one generator per MintHeader entry (so a FullShieldedOutput may claim a
        # freshly-minted asset). Dropped here — MintHeader (0x14) is post-plan.
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

    def verify_authority_restriction(self, tx: Transaction) -> None:
        """Shielded outputs cannot be authority (mint/melt) outputs."""
        from hathorlib.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput
        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, AmountShieldedOutput):
                from hathor.transaction import TxOutput
                if output.token_data & TxOutput.TOKEN_AUTHORITY_MASK:
                    raise ShieldedAuthorityError(
                        f'shielded output {i}: authority outputs cannot be shielded'
                    )
            elif isinstance(output, FullShieldedOutput):
                pass  # FullShieldedOutput has no token_data field, so no authority risk
            else:
                raise InvalidShieldedOutputError(f'shielded output {i}: unknown output type')

    def verify_trivial_commitment_protection(self, tx: Transaction) -> None:
        """Without storage, conservatively require >= 2 shielded outputs always."""
        if not tx.shielded_outputs:
            return
        if len(tx.shielded_outputs) < 2:
            raise TrivialCommitmentError(
                'at least 2 shielded outputs are required '
                f'to prevent trivial commitment matching (got {len(tx.shielded_outputs)})'
            )

    def verify_no_mint_melt(self, token_dict: TokenInfoDict) -> None:
        """Reject mint/melt operations in transactions with shielded outputs."""
        # TODO (mint/melt — postponed): the mint/melt extension REPLACES this forbid-all rule with
        # verify_no_undeclared_mint_melt (which allows *declared* mint/melt via MintHeader/MeltHeader).
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

    def verify_shielded_balance(
        self,
        tx: Transaction,
        *,
        spent_txs: dict[bytes, BaseTransaction] | None = None,
        asset_tag_cache: dict[bytes, bytes] | None = None,
    ) -> None:
        """Homomorphic balance verification.

        For mixed and partial-unshield txs (at least one shielded output):
          sum(C_in) == sum(C_out) + fee*H_HTR
        For full-unshield txs (shielded inputs, no shielded outputs): the tx
        carries an UnshieldBalanceHeader with `excess = sum(r_in) − sum(r_out)`
        and verification checks:
          sum(C_in) == sum(C_out) + excess*G + fee*H_HTR

        Mutual-exclusion invariant: a shielded tx must carry either a
        ShieldedOutputsHeader or an UnshieldBalanceHeader, not both and not
        neither.
        """
        from hathor_ct_crypto import verify_balance

        assert tx.storage is not None
        transparent_inputs: list[tuple[int, bytes]] = []
        shielded_inputs: list[bytes] = []

        for tx_input in tx.inputs:
            spent_tx = spent_txs[tx_input.tx_id] if spent_txs else tx.storage.get_transaction(tx_input.tx_id)
            spent_index = tx_input.index
            if spent_index < len(spent_tx.outputs):
                spent_output = spent_tx.outputs[spent_index]
                if not spent_output.is_token_authority():
                    token_uid = self._normalize_token_uid(spent_tx.get_token_uid(spent_output.get_token_index()))
                    transparent_inputs.append((spent_output.value, token_uid))
            else:
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
            token_uid = self._normalize_token_uid(tx.get_token_uid(output.get_token_index()))
            transparent_outputs.append((output.value, token_uid))

        for shielded_output in tx.shielded_outputs:
            shielded_outputs.append(shielded_output.commitment)

        if tx.has_fees():
            for fee_entry in tx.get_fee_header().get_fees():
                token_uid = self._normalize_token_uid(fee_entry.token_uid)
                transparent_outputs.append((fee_entry.amount, token_uid))

        # TODO (mint/melt — postponed): the mint/melt extension folds MintHeader/MeltHeader entries
        # into an augmented balance equation (RFC Rule M4) via _fold_mint_melt_entry + nc_block_storage.
        # Dropped here — mint/melt (0x14/0x15) is post-plan.
        # Mutual-exclusion invariants on the excess blinding factor:
        #   1) excess and shielded outputs cannot coexist.
        #   2) a tx with shielded inputs and no shielded outputs must carry excess
        #      (otherwise sum(r_in)*G has no counterpart and the equation cannot hold).
        #   3) excess is only meaningful for txs with shielded inputs.
        #
        # Invariant (1) is keyed on ShieldedOutputsHeader *presence*, not on
        # whether the header happens to carry a non-empty commitment list, so
        # a malformed empty-list header can't evade the check.
        has_shielded_outputs_ = tx.has_shielded_outputs()
        has_shielded_inputs_ = bool(shielded_inputs)
        excess_bf = tx.excess_blinding_factor
        has_excess = excess_bf is not None
        if has_shielded_outputs_ and has_excess:
            raise ShieldedBalanceMismatchError(
                'a shielded tx cannot carry both shielded outputs and an unshield balance header'
            )
        if has_shielded_inputs_ and not has_shielded_outputs_ and not has_excess:
            raise ShieldedBalanceMismatchError(
                'a full-unshield tx (shielded inputs, no shielded outputs) must carry an '
                'unshield balance header'
            )
        if has_excess and not has_shielded_inputs_:
            raise ShieldedBalanceMismatchError(
                'unshield balance header requires at least one shielded input'
            )

        try:
            if not verify_balance(
                transparent_inputs,
                shielded_inputs,
                transparent_outputs,
                shielded_outputs,
                excess_bf,
            ):
                raise ShieldedBalanceMismatchError(
                    'shielded balance equation does not hold'
                )
        except ValueError as e:
            raise ShieldedBalanceMismatchError(f'balance verification error: {e}') from e
