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
BLS12-381 cryptography for the two-tier finality fast path.

Finality validators co-sign transactions with BLS signatures so that the votes of a quorum can be
aggregated into a single, compact Finality Certificate that verifies against the committee with one
pairing check. All validators sign the *same* per-transaction pin-message, so we use same-message
aggregation (``FastAggregateVerify``); this is only safe against rogue-key attacks when every
committee public key carries a verified proof-of-possession, which is why we use the
``G2ProofOfPossession`` ciphersuite and validate the PoP when a committee is loaded.

The concrete BLS backend is the native ``blst`` library, reached through our Rust extension
(``htr_lib``); the functions below wrap it so the backend stays swappable without touching the rest of
the codebase. The min-pubkey-size layout and ``G2ProofOfPossession`` ciphersuite are wire-compatible
with the reference ``py_ecc`` implementation (identical keys, signatures and proofs-of-possession for
the same input), so the backend can change without invalidating any existing committee or certificate.
"""

from __future__ import annotations

import hashlib
from typing import NewType, Sequence

import htr_lib
from pydantic import ConfigDict, Field, field_validator, model_validator

from hathor.types import VertexId
from hathor.utils.pydantic import BaseModel, Hex

# Domain-separation tag mixed into the pin-message, so a vote can never be replayed as a signature
# over any other kind of message.
PIN_MESSAGE_TAG = b'hathor-fc-pin-v1'

# Byte lengths for BLS12-381 in the G2 proof-of-possession ciphersuite.
BLS_PRIVATE_KEY_LEN = 32
BLS_PUBLIC_KEY_LEN = 48  # compressed G1 point
BLS_SIGNATURE_LEN = 96  # compressed G2 point

# Length of the (non-unique) validator id used as a skip-hint in votes, mirroring `PoaSignerId`.
VALIDATOR_ID_LEN = 2

# A BLS private key is a scalar (an int in `[1, curve_order)`).
BLSPrivateKey = NewType('BLSPrivateKey', int)
# A BLS public key is a compressed G1 point (`BLS_PUBLIC_KEY_LEN` bytes).
BLSPublicKey = NewType('BLSPublicKey', bytes)
# A BLS signature (and proof-of-possession) is a compressed G2 point (`BLS_SIGNATURE_LEN` bytes).
BLSSignature = NewType('BLSSignature', bytes)
# A non-unique, 2-byte id derived from a validator's public key (skip-hint only, never trusted).
ValidatorId = NewType('ValidatorId', bytes)


def bls_keygen(ikm: bytes) -> BLSPrivateKey:
    """Derive a BLS private key from input key material (>= 32 bytes of entropy)."""
    return BLSPrivateKey(int.from_bytes(htr_lib.bls_keygen(ikm), 'big'))


def bls_sk_to_pk(private_key: BLSPrivateKey) -> BLSPublicKey:
    """Return the compressed public key for a private key."""
    return BLSPublicKey(htr_lib.bls_sk_to_pk(private_key_to_bytes(private_key)))


def bls_pop_prove(private_key: BLSPrivateKey) -> BLSSignature:
    """Produce a proof-of-possession for a private key (defends FastAggregateVerify against
    rogue-key attacks)."""
    return BLSSignature(htr_lib.bls_pop_prove(private_key_to_bytes(private_key)))


def bls_pop_verify(public_key: BLSPublicKey, pop: BLSSignature) -> bool:
    """Verify a proof-of-possession for a public key. Returns False on malformed input."""
    return htr_lib.bls_pop_verify(bytes(public_key), bytes(pop))


def bls_sign(private_key: BLSPrivateKey, message: bytes) -> BLSSignature:
    """Sign a message with a private key."""
    return BLSSignature(htr_lib.bls_sign(private_key_to_bytes(private_key), message))


def bls_verify(public_key: BLSPublicKey, message: bytes, signature: BLSSignature) -> bool:
    """Verify a single signature. Returns False on malformed input (callers handle untrusted data)."""
    return htr_lib.bls_verify(bytes(public_key), message, bytes(signature))


def bls_aggregate(signatures: Sequence[BLSSignature]) -> BLSSignature:
    """Aggregate one or more signatures into a single signature.

    Raises ValueError if the sequence is empty (there is nothing to aggregate). Callers must verify
    each signature individually *before* aggregating: aggregation cannot localize an invalid member,
    so a single bad signature silently poisons the result.
    """
    if not signatures:
        raise ValueError('cannot aggregate an empty sequence of signatures')
    return BLSSignature(htr_lib.bls_aggregate([bytes(sig) for sig in signatures]))


def bls_fast_aggregate_verify(
    public_keys: Sequence[BLSPublicKey],
    message: bytes,
    aggregate_signature: BLSSignature,
) -> bool:
    """Verify an aggregate signature where every signer signed the *same* message.

    Returns False on an empty key set or malformed input.
    """
    if not public_keys:
        return False
    return htr_lib.bls_fast_aggregate_verify(
        [bytes(pk) for pk in public_keys],
        message,
        bytes(aggregate_signature),
    )


def private_key_to_bytes(private_key: BLSPrivateKey) -> bytes:
    """Serialize a private key as 32 big-endian bytes."""
    return int(private_key).to_bytes(BLS_PRIVATE_KEY_LEN, 'big')


def private_key_from_bytes(data: bytes) -> BLSPrivateKey:
    """Parse a private key from its 32 big-endian bytes."""
    if len(data) != BLS_PRIVATE_KEY_LEN:
        raise ValueError(f'private key must be {BLS_PRIVATE_KEY_LEN} bytes, got {len(data)}')
    return BLSPrivateKey(int.from_bytes(data, 'big'))


def get_validator_id(public_key: BLSPublicKey) -> ValidatorId:
    """Return the non-unique validator id (first bytes of the hashed public key).

    Like `PoaSignerId`, this is only a hint to skip unnecessary signature verifications; it is never
    relied upon for correctness or membership.
    """
    return ValidatorId(hashlib.sha256(public_key).digest()[:VALIDATOR_ID_LEN])


def get_pin_message(tx_id: VertexId, committee_hash: bytes) -> bytes:
    """Return the canonical message a validator signs to pin/certify a transaction.

    The message commits to the `tx_id` only: an honest validator pins *every* input of the
    transaction to it before signing, so the pinned set is fully re-derivable from the transaction
    itself during certificate verification. The committee hash binds the signature to a specific
    committee, and the domain tag prevents cross-protocol replay.
    """
    return hashlib.sha256(PIN_MESSAGE_TAG + committee_hash + tx_id).digest()


def generate_validator_keys(ikm: bytes) -> tuple[str, str, str]:
    """Generate a (private_key_hex, public_key_hex, pop_hex) triple for a finality validator.

    Helper for tests and key-generation tooling. `ikm` must be at least 32 bytes of entropy.
    """
    sk = bls_keygen(ikm)
    pk = bls_sk_to_pk(sk)
    pop = bls_pop_prove(sk)
    return private_key_to_bytes(sk).hex(), bytes(pk).hex(), bytes(pop).hex()


class FinalityValidatorSigner:
    """Runtime signer holding a finality validator's BLS private key.

    Mirrors `hathor.consensus.poa.poa_signer.PoaSigner`.
    """

    __slots__ = ('_private_key', '_public_key', '_validator_id')

    def __init__(self, private_key: BLSPrivateKey) -> None:
        self._private_key = private_key
        self._public_key = bls_sk_to_pk(private_key)
        self._validator_id = get_validator_id(self._public_key)

    @property
    def public_key(self) -> BLSPublicKey:
        """Return this validator's compressed public key."""
        return self._public_key

    @property
    def validator_id(self) -> ValidatorId:
        """Return this validator's non-unique skip-hint id."""
        return self._validator_id

    def sign_pin(self, pin_message: bytes) -> BLSSignature:
        """Sign a pin-message (see `get_pin_message`) to vote for a transaction."""
        return bls_sign(self._private_key, pin_message)


class FinalityValidatorSignerFile(BaseModel):
    """A finality validator's key configuration file.

    Mirrors `hathor.consensus.poa.poa_signer.PoaSignerFile`: it carries the hex-encoded private key,
    public key and proof-of-possession, and validates that they are mutually consistent on load.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    private_key: BLSPrivateKey = Field(alias='private_key_hex')
    public_key: Hex[bytes] = Field(alias='public_key_hex')
    pop: Hex[bytes] = Field(alias='pop_hex')

    @field_validator('private_key', mode='before')
    @classmethod
    def _parse_private_key(cls, private_key: str | int) -> BLSPrivateKey:
        """Parse a private key hex string into a scalar."""
        if isinstance(private_key, int):
            return BLSPrivateKey(private_key)
        return private_key_from_bytes(bytes.fromhex(private_key))

    @model_validator(mode='after')
    def _validate_keys(self) -> 'FinalityValidatorSignerFile':
        """Validate that the public key derives from the private key and the PoP is valid."""
        expected_public_key = bls_sk_to_pk(self.private_key)
        if bytes(self.public_key) != bytes(expected_public_key):
            raise ValueError('invalid public key')
        if not bls_pop_verify(BLSPublicKey(bytes(self.public_key)), BLSSignature(bytes(self.pop))):
            raise ValueError('invalid proof-of-possession')
        return self

    def get_signer(self) -> FinalityValidatorSigner:
        """Return a runtime signer for this file."""
        return FinalityValidatorSigner(self.private_key)
