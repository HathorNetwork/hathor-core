#  Copyright 2024 Hathor Labs
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

import pytest

from hathor.simulator.shielded import SHIELDED_CRYPTO_AVAILABLE, build_shielded_output, rewind_shielded_output
from hathor.util import Random
from hathorlib.transaction.shielded_tx_output import (
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
    OutputMode,
)

HTR_UID = b'\x00'
SCRIPT = b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac'  # a plausible P2PKH script


def test_dummy_amount_only_shape() -> None:
    out = build_shielded_output(
        amount=100,
        token_uid=HTR_UID,
        token_data=0,
        script=SCRIPT,
        mode=OutputMode.AMOUNT_ONLY,
        rng=Random(0),
    )
    assert isinstance(out, AmountShieldedOutput)
    assert out.mode() == OutputMode.AMOUNT_ONLY
    assert len(out.commitment) == COMMITMENT_SIZE
    assert out.token_data == 0
    assert out.script == SCRIPT
    assert out.ephemeral_pubkey is not None
    assert len(out.ephemeral_pubkey) == EPHEMERAL_PUBKEY_SIZE
    assert out.ephemeral_pubkey != b'\x00' * EPHEMERAL_PUBKEY_SIZE  # 'present'
    assert 0 < len(out.range_proof) <= 3328


def test_dummy_fully_shielded_shape() -> None:
    out = build_shielded_output(
        amount=100,
        token_uid=HTR_UID,
        token_data=0,
        script=SCRIPT,
        mode=OutputMode.FULLY_SHIELDED,
        rng=Random(0),
    )
    assert isinstance(out, FullShieldedOutput)
    assert out.mode() == OutputMode.FULLY_SHIELDED
    assert len(out.commitment) == COMMITMENT_SIZE
    assert len(out.asset_commitment) == ASSET_COMMITMENT_SIZE
    assert 0 < len(out.surjection_proof) <= 4096


def test_dummy_is_deterministic_with_seeded_rng() -> None:
    a = build_shielded_output(amount=1, token_uid=HTR_UID, token_data=0, script=SCRIPT,
                              mode=OutputMode.AMOUNT_ONLY, rng=Random(42))
    b = build_shielded_output(amount=1, token_uid=HTR_UID, token_data=0, script=SCRIPT,
                              mode=OutputMode.AMOUNT_ONLY, rng=Random(42))
    assert a == b


def test_rewind_unavailable_on_master() -> None:
    if SHIELDED_CRYPTO_AVAILABLE:
        pytest.skip('native CT crypto present; rewind is exercised by the round-trip test')
    out = build_shielded_output(amount=1, token_uid=HTR_UID, token_data=0, script=SCRIPT,
                                mode=OutputMode.AMOUNT_ONLY, rng=Random(0))
    with pytest.raises(RuntimeError, match='native CT crypto not available'):
        rewind_shielded_output(out, b'\x01' * 32, HTR_UID)
