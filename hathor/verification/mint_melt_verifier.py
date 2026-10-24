#  Copyright 2026 Hathor Labs
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

from hathor.conf.settings import HathorSettings
from hathor.transaction.exceptions import (
    ForbiddenMelt,
    ForbiddenMint,
    InvalidMintMeltHeaderError,
    ShieldedMintMeltForbiddenError,
)
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenVersion

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, Transaction
    from hathor.transaction.token_info import TokenInfoDict


class MintMeltVerifier:
    """Verification of the MintHeader / MeltHeader (RFC shielded-outputs mint/melt).

    Extracted from TransactionVerifier so the mint/melt rules live alongside the
    other header verifiers (NanoHeaderVerifier, etc.). No crypto is required for
    any of these checks; the crypto-bound shielded balance rule lives elsewhere.
    """

    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings

    def verify_mint_melt_basic(self, tx: Transaction) -> None:
        """Top-level: basic (no-storage) verification for MintHeader/MeltHeader.

        Fires whenever either header is present. Performs Rules M1, M3, the
        well-formedness checks against tx.tokens length, and the NanoHeader
        same-token guard.
        """
        if not tx.has_mint_header() and not tx.has_melt_header():
            return
        self.verify_mint_melt_headers_well_formed(tx)
        self.verify_mint_melt_requires_shielded(tx)
        self.verify_mint_melt_nano_compatibility(tx)

    def verify_mint_melt_headers_well_formed(self, tx: Transaction) -> None:
        """Per-entry shape and Rule M3 (a token may not appear in both headers).

        Wire-format constraints (count bounds, per-entry token_index in [1, 16],
        amount >= 1, uniqueness within a header) are enforced at deserialize-time.
        Here we additionally bound token_index against tx.tokens length and
        cross-check that no token appears in both MintHeader and MeltHeader.
        """
        mint_indexes: set[int] = set()
        melt_indexes: set[int] = set()
        n_tokens = len(tx.tokens)

        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                if entry.token_index > n_tokens:
                    raise InvalidMintMeltHeaderError(
                        f'MintHeader: token_index {entry.token_index} exceeds '
                        f'tx.tokens length {n_tokens}'
                    )
                mint_indexes.add(entry.token_index)

        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                if entry.token_index > n_tokens:
                    raise InvalidMintMeltHeaderError(
                        f'MeltHeader: token_index {entry.token_index} exceeds '
                        f'tx.tokens length {n_tokens}'
                    )
                melt_indexes.add(entry.token_index)

        # Rule M3: a token cannot appear in both headers.
        overlap = mint_indexes & melt_indexes
        if overlap:
            raise InvalidMintMeltHeaderError(
                f'MintHeader and MeltHeader share token_index(es) {sorted(overlap)}; '
                f'a token cannot be both minted and melted in the same transaction'
            )

    def verify_mint_melt_requires_shielded(self, tx: Transaction) -> None:
        """Rule M1: MintHeader/MeltHeader is valid only on shielded transactions.

        Phase 1 (no storage): "shielded" is detected via header presence —
        ShieldedOutputsHeader covers the mixed/partial-unshield case, and
        UnshieldBalanceHeader covers the full-unshield case (RFC unresolved Q6).
        A tx that carries shielded inputs with neither header would also fail
        here (no shielded marker found), and is independently rejected by the
        parent shielded RFC's mutual-exclusion invariant inside
        verify_shielded_balance — so the storage-bound case is already covered
        upstream and downstream.
        """
        if not tx.has_mint_header() and not tx.has_melt_header():
            return
        if tx.has_shielded_outputs() or tx.has_unshield_balance_header():
            return
        raise ShieldedMintMeltForbiddenError(
            'MintHeader/MeltHeader requires the transaction to carry a '
            'ShieldedOutputsHeader or UnshieldBalanceHeader (Rule M1)'
        )

    def verify_mint_melt_nano_compatibility(self, tx: Transaction) -> None:
        """Reject same-token mint/melt declared via both NanoHeader actions and Mint/Melt headers.

        Per the user's choice on RFC unresolved Q3, a NanoHeader may coexist with
        Mint/Melt headers in the same tx. Cross-token combinations are fine, but
        a single token cannot be minted (or melted) through both channels at once
        because the amount would be ambiguous and the augmented balance equation
        would double-count.
        """
        if not tx.is_nano_contract():
            return
        if not tx.has_mint_header() and not tx.has_melt_header():
            return

        nano_header = tx.get_nano_header()
        nano_action_token_uids: set[bytes] = set()
        for action in nano_header.get_actions():
            nano_action_token_uids.add(action.token_uid)

        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                token_uid = tx.get_token_uid(entry.token_index)
                if token_uid in nano_action_token_uids:
                    raise InvalidMintMeltHeaderError(
                        f'token {token_uid.hex()}: declared in both MintHeader and a '
                        f'NanoHeader action; supply changes must use a single channel per token'
                    )
        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                token_uid = tx.get_token_uid(entry.token_index)
                if token_uid in nano_action_token_uids:
                    raise InvalidMintMeltHeaderError(
                        f'token {token_uid.hex()}: declared in both MeltHeader and a '
                        f'NanoHeader action; supply changes must use a single channel per token'
                    )

    def verify_mint_melt_authority_inputs(
        self,
        tx: Transaction,
        *,
        spent_txs: dict[bytes, BaseTransaction] | None = None,
    ) -> None:
        """Rule M2: every MintHeader/MeltHeader entry needs the matching authority input.

        For each (token_index, amount) in MintHeader, the tx MUST consume at
        least one mint authority input for tx.tokens[token_index - 1]. Symmetric
        for MeltHeader. Authority inputs/outputs remain transparent (parent
        Rule 7), so this check walks `tx.inputs` and inspects each spent
        transparent output.

        TokenCreationTransaction is exempt for token_index=1 (the new token):
        the TCT itself grants both authorities to the issuer, so the MintHeader
        entry for the new token does not require a pre-existing authority input.
        """
        if not tx.has_mint_header() and not tx.has_melt_header():
            return

        assert tx.storage is not None

        # Collect authority sets per token from transparent inputs.
        mint_authorities: set[bytes] = set()
        melt_authorities: set[bytes] = set()
        for tx_input in tx.inputs:
            spent_tx = spent_txs[tx_input.tx_id] if spent_txs else tx.storage.get_transaction(tx_input.tx_id)
            spent_index = tx_input.index
            if spent_index >= len(spent_tx.outputs):
                # Shielded inputs cannot be authority outputs (parent Rule 7).
                continue
            spent_output = spent_tx.outputs[spent_index]
            if not spent_output.is_token_authority():
                continue
            token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
            if spent_output.can_mint_token():
                mint_authorities.add(token_uid)
            if spent_output.can_melt_token():
                melt_authorities.add(token_uid)

        is_tct = isinstance(tx, TokenCreationTransaction)

        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                token_uid = tx.get_token_uid(entry.token_index)
                if is_tct and entry.token_index == 1:
                    # The new token's authority is granted by the TCT itself.
                    continue
                if token_uid not in mint_authorities:
                    raise ForbiddenMint(entry.amount, token_uid)

        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                token_uid = tx.get_token_uid(entry.token_index)
                if is_tct and entry.token_index == 1:
                    continue
                if token_uid not in melt_authorities:
                    raise ForbiddenMelt.from_token(entry.amount, token_uid)

    def verify_no_undeclared_mint_melt(self, tx: Transaction, token_dict: TokenInfoDict) -> None:
        """Reject mint/melt that is not declared via MintHeader/MeltHeader.

        Shielded txs hide non-HTR amounts, so transparent token_dict surplus/deficit
        on a non-NATIVE token is only legitimate when covered by a corresponding
        Mint/Melt header entry. Without the header, there is no public scalar to
        feed the augmented balance equation (Rule M4) and the prover could mint
        from nothing.
        """
        mint_token_uids: set[bytes] = set()
        melt_token_uids: set[bytes] = set()
        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                mint_token_uids.add(tx.get_token_uid(entry.token_index))
        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                melt_token_uids.add(tx.get_token_uid(entry.token_index))

        for token_uid, token_info in token_dict.items():
            if token_info.version == TokenVersion.NATIVE:
                continue
            if token_info.can_mint and token_info.has_been_minted() and token_uid not in mint_token_uids:
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: undeclared mint in shielded tx '
                    f'(transparent surplus: {token_info.amount}); declare via MintHeader'
                )
            if token_info.can_melt and token_info.has_been_melted() and token_uid not in melt_token_uids:
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: undeclared melt in shielded tx '
                    f'(transparent deficit: {token_info.amount}); declare via MeltHeader'
                )
