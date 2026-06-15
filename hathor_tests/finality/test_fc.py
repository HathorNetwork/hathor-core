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

import hashlib

import pytest

from hathor.finality.crypto import (
    BLSSignature,
    FinalityValidatorSigner,
    bls_aggregate,
    bls_keygen,
    bls_pop_prove,
    get_pin_message,
    private_key_to_bytes,
)
from hathor.finality.fc import (
    FinalityCertificate,
    Vote,
    bitmap_from_indices,
    indices_from_bitmap,
)
from hathor.finality.finality_settings import FinalitySettings, FinalityValidatorSettings
from hathor.types import VertexId


def _build_committee(
    n: int,
    weights: list[int] | None = None,
) -> tuple[FinalitySettings, list[FinalityValidatorSigner]]:
    """Build a committee of `n` validators and return (settings, signers) in committee-index order."""
    weights = weights or [1] * n
    signers = []
    validator_settings = []
    for i in range(n):
        sk = bls_keygen(hashlib.sha256(f'fc-committee-{i}'.encode()).digest())
        signer = FinalityValidatorSigner(sk)
        signers.append(signer)
        validator_settings.append(
            FinalityValidatorSettings(
                public_key=bytes(signer.public_key).hex(),
                pop=bytes(bls_pop_prove(sk)).hex(),
                weight=weights[i],
            )
        )
    settings = FinalitySettings(enabled=True, validators=tuple(validator_settings))
    return settings, signers


def _make_certificate(
    settings: FinalitySettings,
    signers: list[FinalityValidatorSigner],
    tx_id: VertexId,
    signer_indices: list[int],
) -> FinalityCertificate:
    pin_message = get_pin_message(tx_id, settings.calculate_committee_hash())
    sigs = [signers[i].sign_pin(pin_message) for i in signer_indices]
    agg = bls_aggregate(sigs)
    return FinalityCertificate(tx_id=tx_id, bitmap=bitmap_from_indices(signer_indices), agg_signature=agg)


def test_bitmap_helpers() -> None:
    assert bitmap_from_indices([0, 2, 3]) == 0b1101
    assert indices_from_bitmap(0b1101) == [0, 2, 3]
    assert indices_from_bitmap(0) == []


def test_vote_serialization_round_trip() -> None:
    settings, signers = _build_committee(4)
    tx_id = VertexId(b'\x11' * 32)
    pin_message = get_pin_message(tx_id, settings.calculate_committee_hash())
    vote = Vote(
        tx_id=tx_id,
        validator_id=signers[0].validator_id,
        signature=signers[0].sign_pin(pin_message),
    )
    raw = bytes(vote)
    assert len(raw) == 32 + 2 + 96
    assert Vote.from_bytes(raw) == vote


def test_vote_from_bytes_rejects_bad_length() -> None:
    with pytest.raises(ValueError):
        Vote.from_bytes(b'\x00' * 10)


def test_certificate_serialization_round_trip() -> None:
    settings, signers = _build_committee(4)
    tx_id = VertexId(b'\x22' * 32)
    fc = _make_certificate(settings, signers, tx_id, [0, 1, 2])
    raw = bytes(fc)
    restored = FinalityCertificate.from_bytes(raw)
    assert restored == fc


def test_certificate_from_bytes_rejects_inconsistent_length() -> None:
    with pytest.raises(ValueError):
        FinalityCertificate.from_bytes(b'\x00' * 10)
    settings, signers = _build_committee(4)
    fc = _make_certificate(settings, signers, VertexId(b'\x33' * 32), [0, 1, 2])
    with pytest.raises(ValueError):
        FinalityCertificate.from_bytes(bytes(fc) + b'\x00')


def test_certificate_verifies_with_quorum() -> None:
    # n = 4, f = 1, quorum = 3.
    settings, signers = _build_committee(4)
    tx_id = VertexId(b'\x44' * 32)
    fc = _make_certificate(settings, signers, tx_id, [0, 1, 2])
    assert fc.verify(settings)


def test_certificate_rejected_below_quorum() -> None:
    settings, signers = _build_committee(4)
    tx_id = VertexId(b'\x55' * 32)
    fc = _make_certificate(settings, signers, tx_id, [0, 1])  # weight 2 < quorum 3
    assert not fc.verify(settings)


def test_certificate_rejected_for_wrong_tx_id() -> None:
    # A valid aggregate over tx A must not verify when presented as a certificate for tx B, because
    # the pin-message commits to the tx_id.
    settings, signers = _build_committee(4)
    pin_message = get_pin_message(VertexId(b'\xaa' * 32), settings.calculate_committee_hash())
    agg = bls_aggregate([signers[i].sign_pin(pin_message) for i in [0, 1, 2]])
    forged = FinalityCertificate(tx_id=VertexId(b'\xbb' * 32), bitmap=bitmap_from_indices([0, 1, 2]),
                                 agg_signature=agg)
    assert not forged.verify(settings)


def test_certificate_rejected_when_bitmap_does_not_match_signers() -> None:
    # The aggregate is over signers {0,1,2} but the bitmap claims {0,1,3}: verification must fail
    # because the reconstructed public-key set does not match the actual signers.
    settings, signers = _build_committee(4)
    tx_id = VertexId(b'\x66' * 32)
    pin_message = get_pin_message(tx_id, settings.calculate_committee_hash())
    agg = bls_aggregate([signers[i].sign_pin(pin_message) for i in [0, 1, 2]])
    mismatched = FinalityCertificate(tx_id=tx_id, bitmap=bitmap_from_indices([0, 1, 3]), agg_signature=agg)
    assert not mismatched.verify(settings)


def test_certificate_rejected_with_garbage_signature() -> None:
    settings, signers = _build_committee(4)
    fc = FinalityCertificate(
        tx_id=VertexId(b'\x77' * 32),
        bitmap=bitmap_from_indices([0, 1, 2]),
        agg_signature=BLSSignature(b'\x00' * 96),
    )
    assert not fc.verify(settings)


def test_weighted_committee_certificate() -> None:
    # Weights 3+3+3+1=10 -> quorum 7. Signers {0,1} have weight 6 (< 7); add signer 3 -> 7.
    settings, signers = _build_committee(4, weights=[3, 3, 3, 1])
    tx_id = VertexId(b'\x88' * 32)
    assert not _make_certificate(settings, signers, tx_id, [0, 1]).verify(settings)
    assert _make_certificate(settings, signers, tx_id, [0, 1, 3]).verify(settings)


def test_unused_import_guard() -> None:
    # private_key_to_bytes is part of the public crypto API used by tooling; keep a smoke reference.
    assert len(private_key_to_bytes(bls_keygen(b'\x09' * 32))) == 32
