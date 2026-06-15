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
from pydantic import ValidationError

from hathor.finality.crypto import (
    BLS_PUBLIC_KEY_LEN,
    BLS_SIGNATURE_LEN,
    PIN_MESSAGE_TAG,
    VALIDATOR_ID_LEN,
    BLSPublicKey,
    BLSSignature,
    FinalityValidatorSigner,
    FinalityValidatorSignerFile,
    bls_aggregate,
    bls_fast_aggregate_verify,
    bls_keygen,
    bls_pop_prove,
    bls_pop_verify,
    bls_sign,
    bls_sk_to_pk,
    bls_verify,
    generate_validator_keys,
    get_pin_message,
    get_validator_id,
    private_key_from_bytes,
    private_key_to_bytes,
)


def _ikm(seed: int) -> bytes:
    """Deterministic 32-byte input key material for a test validator."""
    return hashlib.sha256(f'finality-test-{seed}'.encode()).digest()


def test_sign_and_verify_round_trip() -> None:
    sk = bls_keygen(_ikm(1))
    pk = bls_sk_to_pk(sk)
    assert len(pk) == BLS_PUBLIC_KEY_LEN

    message = b'a transaction id' * 2
    sig = bls_sign(sk, message)
    assert len(sig) == BLS_SIGNATURE_LEN
    assert bls_verify(pk, message, sig)
    assert not bls_verify(pk, b'a different message', sig)


def test_proof_of_possession() -> None:
    sk = bls_keygen(_ikm(2))
    pk = bls_sk_to_pk(sk)
    pop = bls_pop_prove(sk)
    assert bls_pop_verify(pk, pop)

    # A PoP from a different key must not verify against this public key.
    other_pop = bls_pop_prove(bls_keygen(_ikm(3)))
    assert not bls_pop_verify(pk, other_pop)


def test_verify_handles_malformed_input() -> None:
    sk = bls_keygen(_ikm(4))
    pk = bls_sk_to_pk(sk)
    # Wrong-length public key / signature must return False, not raise (untrusted network data).
    assert not bls_verify(BLSPublicKey(b'\x00' * 10), b'msg', bls_sign(sk, b'msg'))
    assert not bls_verify(pk, b'msg', BLSSignature(b'\x00' * 10))
    assert not bls_pop_verify(BLSPublicKey(b'\x00' * 10), BLSSignature(b'\x00' * 10))


def test_fast_aggregate_verify_same_message() -> None:
    signers = [bls_keygen(_ikm(i)) for i in range(4)]
    pks = [bls_sk_to_pk(sk) for sk in signers]
    message = get_pin_message(b'\x11' * 32, committee_hash=b'\x22' * 32)

    sigs = [bls_sign(sk, message) for sk in signers]
    agg = bls_aggregate(sigs)

    assert bls_fast_aggregate_verify(pks, message, agg)
    # A strict subset of the signers must not verify the full aggregate.
    assert not bls_fast_aggregate_verify(pks[:3], message, agg)
    # The aggregate must not verify against a different message.
    assert not bls_fast_aggregate_verify(pks, b'other', agg)


def test_fast_aggregate_verify_rejects_empty_and_malformed() -> None:
    assert not bls_fast_aggregate_verify([], b'msg', BLSSignature(b'\x00' * BLS_SIGNATURE_LEN))
    pk = bls_sk_to_pk(bls_keygen(_ikm(9)))
    assert not bls_fast_aggregate_verify([pk], b'msg', BLSSignature(b'\x00' * 10))


def test_aggregate_empty_raises() -> None:
    with pytest.raises(ValueError):
        bls_aggregate([])


def test_private_key_byte_round_trip() -> None:
    sk = bls_keygen(_ikm(5))
    data = private_key_to_bytes(sk)
    assert len(data) == 32
    assert private_key_from_bytes(data) == sk

    with pytest.raises(ValueError):
        private_key_from_bytes(b'\x00' * 31)


def test_validator_id_is_hash_prefix() -> None:
    pk = bls_sk_to_pk(bls_keygen(_ikm(6)))
    validator_id = get_validator_id(pk)
    assert len(validator_id) == VALIDATOR_ID_LEN
    assert validator_id == hashlib.sha256(pk).digest()[:VALIDATOR_ID_LEN]


def test_get_pin_message_is_domain_separated() -> None:
    tx_id = b'\xab' * 32
    committee_hash = b'\xcd' * 32
    msg = get_pin_message(tx_id, committee_hash)
    assert msg == hashlib.sha256(PIN_MESSAGE_TAG + committee_hash + tx_id).digest()

    # Distinct tx_id or committee_hash must yield a distinct message.
    assert msg != get_pin_message(b'\xac' * 32, committee_hash)
    assert msg != get_pin_message(tx_id, b'\xce' * 32)


def test_signer_signs_pin_message() -> None:
    sk = bls_keygen(_ikm(7))
    signer = FinalityValidatorSigner(sk)
    assert signer.public_key == bls_sk_to_pk(sk)
    assert signer.validator_id == get_validator_id(signer.public_key)

    pin_message = get_pin_message(b'\x01' * 32, committee_hash=b'\x02' * 32)
    sig = signer.sign_pin(pin_message)
    assert bls_verify(signer.public_key, pin_message, sig)


def test_signer_file_round_trip() -> None:
    private_hex, public_hex, pop_hex = generate_validator_keys(_ikm(8))
    file = FinalityValidatorSignerFile.model_validate(
        dict(private_key_hex=private_hex, public_key_hex=public_hex, pop_hex=pop_hex)
    )
    signer = file.get_signer()
    assert bytes(signer.public_key).hex() == public_hex


def test_signer_file_rejects_mismatched_public_key() -> None:
    private_hex, _public_hex, pop_hex = generate_validator_keys(_ikm(10))
    _, wrong_public_hex, _ = generate_validator_keys(_ikm(11))
    with pytest.raises(ValidationError):
        FinalityValidatorSignerFile.model_validate(
            dict(private_key_hex=private_hex, public_key_hex=wrong_public_hex, pop_hex=pop_hex)
        )


def test_signer_file_rejects_invalid_pop() -> None:
    private_hex, public_hex, _pop_hex = generate_validator_keys(_ikm(12))
    _, _, wrong_pop_hex = generate_validator_keys(_ikm(13))
    with pytest.raises(ValidationError):
        FinalityValidatorSignerFile.model_validate(
            dict(private_key_hex=private_hex, public_key_hex=public_hex, pop_hex=wrong_pop_hex)
        )
