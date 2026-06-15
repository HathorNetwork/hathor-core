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

from hathor.finality.crypto import generate_validator_keys
from hathor.finality.finality_settings import FinalitySettings, FinalityValidatorSettings


def _validator(seed: int, weight: int = 1) -> FinalityValidatorSettings:
    ikm = hashlib.sha256(f'committee-{seed}'.encode()).digest()
    _private_hex, public_hex, pop_hex = generate_validator_keys(ikm)
    return FinalityValidatorSettings(public_key=public_hex, pop=pop_hex, weight=weight)


def test_disabled_by_default() -> None:
    settings = FinalitySettings()
    assert settings.enabled is False
    assert settings.validators == ()


def test_enabled_requires_validators() -> None:
    with pytest.raises(ValidationError):
        FinalitySettings(enabled=True, validators=())


def test_quorum_derivation_equal_weights() -> None:
    # n = 4 equal-weight validators -> W = 4, f = 1, quorum = 3.
    settings = FinalitySettings(enabled=True, validators=tuple(_validator(i) for i in range(4)))
    assert settings.total_weight == 4
    assert settings.f == 1
    assert settings.quorum_threshold == 3


def test_quorum_derivation_weighted() -> None:
    # Weights 3 + 3 + 3 + 1 = 10 -> f = 3, quorum = 7.
    settings = FinalitySettings(
        enabled=True,
        validators=(_validator(0, 3), _validator(1, 3), _validator(2, 3), _validator(3, 1)),
    )
    assert settings.total_weight == 10
    assert settings.f == 3
    assert settings.quorum_threshold == 7


def test_reaches_quorum_is_weight_based() -> None:
    settings = FinalitySettings(
        enabled=True,
        validators=(_validator(0, 3), _validator(1, 3), _validator(2, 3), _validator(3, 1)),
    )
    # quorum_threshold == 7
    assert settings.weight_of_bitmap(0b0001) == 3
    assert not settings.reaches_quorum(0b0011)  # 3 + 3 = 6 < 7
    assert settings.reaches_quorum(0b0111)  # 3 + 3 + 3 = 9 >= 7
    # Three low-index validators reach quorum; two heavy + the light one also: 3 + 3 + 1 = 7.
    assert settings.reaches_quorum(0b1011)


def test_public_keys_for_bitmap_matches_index_order() -> None:
    validators = tuple(_validator(i) for i in range(4))
    settings = FinalitySettings(enabled=True, validators=validators)
    assert settings.public_keys == tuple(bytes(v.public_key) for v in validators)
    selected = settings.public_keys_for_bitmap(0b0101)
    assert selected == [bytes(validators[0].public_key), bytes(validators[2].public_key)]
    for i, v in enumerate(validators):
        assert settings.get_validator_index(bytes(v.public_key)) == i
    assert settings.get_validator_index(b'\x00' * 48) is None


def test_rejects_duplicate_validators() -> None:
    v = _validator(7)
    with pytest.raises(ValidationError):
        FinalitySettings(enabled=True, validators=(v, v))


def test_rejects_invalid_pop() -> None:
    good = _validator(8)
    _, _, wrong_pop = generate_validator_keys(hashlib.sha256(b'other').digest())
    bad = FinalityValidatorSettings(public_key=bytes(good.public_key).hex(), pop=wrong_pop)
    with pytest.raises(ValidationError):
        FinalitySettings(enabled=True, validators=(bad,))


def test_committee_hash_is_stable_and_distinct() -> None:
    validators = tuple(_validator(i) for i in range(3))
    settings_a = FinalitySettings(enabled=True, validators=validators)
    settings_b = FinalitySettings(enabled=True, validators=validators)
    assert settings_a.calculate_committee_hash() == settings_b.calculate_committee_hash()
    assert len(settings_a.calculate_committee_hash()) == 32

    settings_c = FinalitySettings(enabled=True, validators=validators + (_validator(99),))
    assert settings_c.calculate_committee_hash() != settings_a.calculate_committee_hash()


def test_public_key_length_validation() -> None:
    with pytest.raises(ValidationError):
        FinalityValidatorSettings(public_key='aa', pop='bb' * 96)
