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
from unittest.mock import Mock

from hathor.finality.crypto import FinalityValidatorSigner, bls_keygen, bls_pop_prove, get_pin_message
from hathor.finality.fc import Vote
from hathor.finality.finality_settings import FinalitySettings, FinalityValidatorSettings
from hathor.finality.pending_pool import PendingFinalityPool
from hathor.types import VertexId

TX_ID = VertexId(b'\x44' * 32)


def _committee(n: int) -> tuple[FinalitySettings, list[FinalityValidatorSigner]]:
    signers, validators = [], []
    for i in range(n):
        sk = bls_keygen(hashlib.sha256(f'pp-{i}'.encode()).digest())
        signer = FinalityValidatorSigner(sk)
        signers.append(signer)
        validators.append(FinalityValidatorSettings(
            public_key=bytes(signer.public_key).hex(),
            pop=bytes(bls_pop_prove(sk)).hex(),
        ))
    return FinalitySettings(enabled=True, validators=tuple(validators)), signers


def _vote(signer: FinalityValidatorSigner, settings: FinalitySettings, tx_id: VertexId) -> Vote:
    msg = get_pin_message(tx_id, settings.calculate_committee_hash())
    return Vote(tx_id=tx_id, validator_id=signer.validator_id, signature=signer.sign_pin(msg))


def _fake_tx(tx_id: VertexId) -> Mock:
    tx = Mock()
    tx.hash = bytes(tx_id)
    return tx


def test_add_tx_is_idempotent() -> None:
    pool = PendingFinalityPool()
    tx = _fake_tx(TX_ID)
    assert pool.add_tx(tx) is True
    assert pool.add_tx(tx) is False
    assert TX_ID in pool
    assert pool.get_tx(TX_ID) is tx
    assert len(pool) == 1


def test_quorum_assembly_and_certificate() -> None:
    settings, signers = _committee(4)  # f = 1, quorum = 3
    pool = PendingFinalityPool()
    pool.add_tx(_fake_tx(TX_ID))

    # Two votes are not enough.
    pool.add_vote(TX_ID, 0, _vote(signers[0], settings, TX_ID))
    pool.add_vote(TX_ID, 1, _vote(signers[1], settings, TX_ID))
    assert not pool.is_ready(TX_ID, settings)
    assert pool.assemble_certificate(TX_ID, settings) is None

    # The third distinct vote reaches quorum and yields a verifiable certificate.
    pool.add_vote(TX_ID, 2, _vote(signers[2], settings, TX_ID))
    assert pool.is_ready(TX_ID, settings)
    fc = pool.assemble_certificate(TX_ID, settings)
    assert fc is not None
    assert fc.verify(settings)


def test_duplicate_validator_votes_are_ignored() -> None:
    settings, signers = _committee(4)
    pool = PendingFinalityPool()
    pool.add_tx(_fake_tx(TX_ID))
    assert pool.add_vote(TX_ID, 0, _vote(signers[0], settings, TX_ID)) is True
    # Same validator index again is ignored (anti-double-count).
    assert pool.add_vote(TX_ID, 0, _vote(signers[0], settings, TX_ID)) is False
    assert pool.get_bitmap(TX_ID) == 0b0001


def test_vote_for_unknown_tx_is_ignored() -> None:
    settings, signers = _committee(4)
    pool = PendingFinalityPool()
    assert pool.add_vote(TX_ID, 0, _vote(signers[0], settings, TX_ID)) is False


def test_remove_drops_entry() -> None:
    pool = PendingFinalityPool()
    pool.add_tx(_fake_tx(TX_ID))
    pool.remove(TX_ID)
    assert TX_ID not in pool
    assert pool.get_tx(TX_ID) is None
