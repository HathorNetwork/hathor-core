# Copyright 2026 Hathor Labs
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

"""
The finality service: the orchestrator of the validator fast path.

It runs on every node that has two-tier finality enabled. On a **validator** node it also holds a
signer and participates in the committee gossip: it applies the voting rule (pinning every input
before signing), floods its vote, accumulates votes, and — when a quorum is reached — assembles the
Finality Certificate and broadcasts the certified transaction to the whole network. On any node it
verifies incoming certificates independently before admitting the certified transaction to the
mempool, and forwards locally-submitted finality transactions to a validator.

Network and storage effects are reached through the injected `FinalityTransport` and callbacks, so
the protocol logic here is independent of the p2p and storage machinery and can be unit-tested in
isolation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Optional, Protocol

from structlog import get_logger

from hathor.finality.crypto import (
    FinalityValidatorSigner,
    bls_verify,
    get_pin_message,
    get_validator_id,
)
from hathor.finality.fc import FinalityCertificate, Vote
from hathor.transaction import Transaction
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId

if TYPE_CHECKING:  # pragma: no cover
    from hathor.finality.finality_settings import FinalitySettings
    from hathor.finality.pending_pool import PendingFinalityPool
    from hathor.finality.stores import FinalityCertificateStore, FinalityPinStore
    from hathor.pubsub import EventArguments, HathorEvents

logger = get_logger()


class FinalityTransport(Protocol):
    """Network effects the finality service needs. Implemented by the p2p layer."""

    def submit_to_validator(self, tx_bytes: bytes) -> None:
        """Send a pending transaction to one (random) committee validator."""
        ...

    def flood_to_validators(self, tx_bytes: bytes, *, exclude: object | None = None) -> None:
        """Flood a pending transaction to committee validators (except ``exclude``)."""
        ...

    def flood_vote(self, vote_bytes: bytes, *, exclude: object | None = None) -> None:
        """Flood a vote to committee validators (except ``exclude``)."""
        ...

    def broadcast_certificate(self, tx_bytes: bytes, fc_bytes: bytes, *, exclude: object | None = None) -> None:
        """Broadcast a certified transaction and its certificate to all peers (except ``exclude``)."""
        ...


class FinalityService:
    """Orchestrates the finality fast path on a node (validator or not)."""

    def __init__(
        self,
        *,
        finality_settings: 'FinalitySettings',
        pending_pool: 'PendingFinalityPool',
        certificate_store: 'FinalityCertificateStore',
        transport: FinalityTransport,
        admit_certified_tx: Callable[[Transaction], bool],
        is_feature_active: Callable[[], bool],
        signer: Optional[FinalityValidatorSigner] = None,
        pin_store: Optional['FinalityPinStore'] = None,
    ) -> None:
        self._log = logger.new()
        self._settings = finality_settings
        self._pending = pending_pool
        self._certificates = certificate_store
        self._transport = transport
        self._admit_certified_tx = admit_certified_tx
        self._is_feature_active = is_feature_active
        self._signer = signer
        self._pin_store = pin_store
        # A validator must have both a signer and a pin store.
        assert (signer is None) == (pin_store is None), 'a validator needs both a signer and a pin store'
        self._committee_hash = finality_settings.calculate_committee_hash() if finality_settings.enabled else b''

    @property
    def is_validator(self) -> bool:
        """Return whether this node is a finality validator."""
        return self._signer is not None

    def _pin_message(self, tx_id: VertexId) -> bytes:
        return get_pin_message(tx_id, self._committee_hash)

    @staticmethod
    def is_eligible(vertex: object) -> bool:
        """Return whether a vertex takes the UTXO finality fast path (a non-nano transaction with inputs)."""
        return (
            isinstance(vertex, Transaction)
            and not vertex.is_nano_contract()
            and len(vertex.inputs) > 0
        )

    def should_divert_to_pending(self, vertex: object) -> bool:
        """Return whether a vertex must be kept out of the mempool until it has a certificate.

        True for a finality-eligible transaction, while the feature is active, that does not yet have a
        known certificate. The mempool-admission gate uses this to divert such transactions.
        """
        if not self._is_feature_active():
            return False
        if not self.is_eligible(vertex):
            return False
        assert isinstance(vertex, Transaction)
        return not self._certificates.has_certificate(vertex.hash)

    # ------------------------------------------------------------------
    # Submission (any node)
    # ------------------------------------------------------------------

    def submit_local_transaction(self, tx: Transaction) -> None:
        """Handle a finality transaction created/submitted locally (e.g. by the wallet/API).

        The transaction is kept in the pending pool and forwarded to a validator (or voted on directly
        if this node is itself a validator). It is *not* added to the mempool until it is certified.
        """
        if not self._is_feature_active() or not self.is_eligible(tx):
            return
        self._pending.add_tx(tx)
        if self.is_validator:
            self._handle_as_validator(tx, source=None)
        else:
            self._transport.submit_to_validator(bytes(tx.get_struct()))

    # ------------------------------------------------------------------
    # Validator gossip
    # ------------------------------------------------------------------

    def on_submit_finality_tx(self, tx: Transaction, *, source: object | None = None) -> None:
        """Handle a pending transaction received from a peer (a submitter or another validator)."""
        if not self._is_feature_active() or not self.is_eligible(tx):
            return
        if self._certificates.has_certificate(tx.hash):
            return
        if not self.is_validator:
            # A non-validator that received a submission just forwards it to a validator.
            self._transport.submit_to_validator(bytes(tx.get_struct()))
            return
        self._handle_as_validator(tx, source=source)

    def _handle_as_validator(self, tx: Transaction, *, source: object | None) -> None:
        """Validator-side: flood the tx to peers, then vote and flood the vote."""
        is_new = self._pending.add_tx(tx)
        if is_new:
            self._transport.flood_to_validators(bytes(tx.get_struct()), exclude=source)
        vote = self._try_vote(tx)
        if vote is not None:
            self._ingest_vote(tx.hash, vote, source=None)

    def _try_vote(self, tx: Transaction) -> Optional[Vote]:
        """Apply the voting rule and, if it passes, pin every input and return a signed vote.

        Returns None (no vote) if the transaction is not eligible, conflicts with the DAG, or any input
        is already pinned to a different transaction (equivocation), or a dependency is missing (defer).
        """
        assert self._signer is not None and self._pin_store is not None
        if self._certificates.has_certificate(tx.hash):
            return None
        try:
            if tx.is_double_spending() or tx.is_spending_voided_tx():
                return None
        except TransactionDoesNotExist:
            # A dependency is not yet known: defer (the parent's certificate may still arrive).
            return None

        outpoints = [(VertexId(txin.tx_id), txin.index) for txin in tx.inputs]
        # First check no input is already pinned to a different transaction.
        for tx_id, index in outpoints:
            existing = self._pin_store.get_pin(tx_id, index)
            if existing is not None and existing != bytes(tx.hash):
                return None
        # Atomically pin every input to this transaction; abort (without signing) on any conflict.
        for tx_id, index in outpoints:
            if not self._pin_store.try_pin(tx_id, index, VertexId(tx.hash)):
                return None

        signature = self._signer.sign_pin(self._pin_message(tx.hash))
        return Vote(tx_id=VertexId(tx.hash), validator_id=self._signer.validator_id, signature=signature)

    def on_vote(self, vote: Vote, *, source: object | None = None) -> None:
        """Handle a vote received from a committee peer."""
        if not self._is_feature_active() or not self.is_validator:
            return
        self._ingest_vote(vote.tx_id, vote, source=source)

    def _ingest_vote(self, tx_id: VertexId, vote: Vote, *, source: object | None) -> None:
        """Verify, record and re-flood a vote; certify if it completes a quorum."""
        if self._certificates.has_certificate(tx_id):
            return
        if tx_id not in self._pending:
            # We do not have the transaction yet; drop the vote (it will be re-gossiped with the tx).
            return
        index = self._resolve_vote_signer(vote)
        if index is None:
            return
        if not self._pending.add_vote(tx_id, index, vote):
            return
        self._transport.flood_vote(bytes(vote), exclude=source)
        if self._pending.is_ready(tx_id, self._settings):
            self._certify(tx_id)

    def _resolve_vote_signer(self, vote: Vote) -> Optional[int]:
        """Return the committee index of the validator that produced ``vote``, or None if invalid.

        The vote carries only a non-unique hint, so we verify the signature against each committee key
        whose hint matches and return the index of the one that verifies.
        """
        pin_message = self._pin_message(vote.tx_id)
        for index, public_key in enumerate(self._settings.public_keys):
            if get_validator_id(public_key) != vote.validator_id:
                continue
            if bls_verify(public_key, pin_message, vote.signature):
                return index
        return None

    def _certify(self, tx_id: VertexId) -> None:
        """Assemble the certificate for a quorum-reached transaction and release it to the network."""
        certificate = self._pending.assemble_certificate(tx_id, self._settings)
        tx = self._pending.get_tx(tx_id)
        if certificate is None or tx is None:
            return
        self._accept_certificate(tx, certificate, source=None)

    # ------------------------------------------------------------------
    # Certificate ingestion (every node)
    # ------------------------------------------------------------------

    def on_certificate(
        self,
        tx: Transaction,
        certificate: FinalityCertificate,
        *,
        source: object | None = None,
    ) -> None:
        """Handle a certified transaction received from a peer: verify, store, admit, and re-broadcast."""
        if not self._is_feature_active() or not self.is_eligible(tx):
            return
        if tx.hash != certificate.tx_id:
            return
        if self._certificates.has_certificate(tx.hash):
            return
        self._accept_certificate(tx, certificate, source=source)

    def _accept_certificate(self, tx: Transaction, certificate: FinalityCertificate, *, source: object | None) -> None:
        """Independently verify a certificate, store it, admit the tx, and re-broadcast."""
        if not certificate.verify(self._settings):
            self._log.warn('rejecting invalid finality certificate', tx=tx.hash_hex)
            return
        self._certificates.add_certificate(tx.hash, bytes(certificate))
        self._pending.remove(tx.hash)
        self._admit_certified_tx(tx)
        self._transport.broadcast_certificate(bytes(tx.get_struct()), bytes(certificate), exclude=source)

    # ------------------------------------------------------------------
    # Settlement housekeeping (validators)
    # ------------------------------------------------------------------

    def handle_consensus_event(self, key: 'HathorEvents', args: 'EventArguments') -> None:
        """Pubsub adapter: release pins for transactions that have been settled by a block."""
        self.on_settlement(args.tx)

    def on_settlement(self, vertex: object) -> None:
        """Release a validator's pins once a transaction is hard-settled by a block.

        Safety does not depend on this — a consumed UTXO can never be re-spent — so it is pure
        housekeeping that frees pin storage (and, in the future, unwedges equivocated UTXOs).
        """
        if self._pin_store is None or not isinstance(vertex, Transaction):
            return
        meta = vertex.get_metadata()
        if meta.first_block is None or meta.voided_by:
            return
        self._pin_store.unpin_resolved(
            [(VertexId(txin.tx_id), txin.index) for txin in vertex.inputs]
        )
