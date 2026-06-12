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

"""Serialization, deserialization and feature-gating of the MintHeader / MeltHeader.

This is the parse-only scaffold for the mint/melt headers: it covers wire-format
round-trips, malformed-input rejection, and the ``ENABLE_SHIELDED_TRANSACTIONS``
gate. No supply/balance semantics are exercised here — those live in the
verification PR.
"""

import dataclasses
from collections.abc import Callable
from unittest.mock import Mock

import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import FeatureSetting, HathorSettings
from hathor.feature_activation.utils import Features
from hathor.serialization import Deserializer
from hathor.transaction import Transaction
from hathor.transaction.exceptions import InvalidMintMeltHeaderError
from hathor.transaction.headers import MeltHeader, MintHeader, MintMeltEntry, VertexHeaderId
from hathor.transaction.vertex_parser._mint_melt_header import deserialize_melt_header, deserialize_mint_header
from hathor.transaction.vertex_parser._vertex_parser import VertexParser
from hathor.verification.verification_params import VerificationParams
from hathor.verification.vertex_verifier import VertexVerifier

MINT_MELT_HEADER_IDS = [VertexHeaderId.MINT_HEADER, VertexHeaderId.MELT_HEADER]

_HeaderCls = type[MintHeader] | type[MeltHeader]
_HeaderDeserializer = Callable[[Deserializer], list[MintMeltEntry]]

# (header class, header-id byte, framework deserializer) for each mint/melt header.
CASES: list[tuple[_HeaderCls, VertexHeaderId, _HeaderDeserializer]] = [
    (MintHeader, VertexHeaderId.MINT_HEADER, deserialize_mint_header),
    (MeltHeader, VertexHeaderId.MELT_HEADER, deserialize_melt_header),
]


@pytest.fixture
def settings_off() -> HathorSettings:
    """Default unittests settings — ENABLE_SHIELDED_TRANSACTIONS is disabled."""
    settings = get_global_settings()
    assert not settings.ENABLE_SHIELDED_TRANSACTIONS
    return settings


@pytest.fixture
def settings_on(settings_off: HathorSettings) -> HathorSettings:
    """Same settings but with ENABLE_SHIELDED_TRANSACTIONS enabled."""
    settings = settings_off.model_copy(update={'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED})
    assert settings.ENABLE_SHIELDED_TRANSACTIONS
    return settings


# --- entry validation -------------------------------------------------------

def test_entry_bounds() -> None:
    # token_index in [1, 16]; HTR (index 0) is forbidden.
    with pytest.raises(ValueError):
        MintMeltEntry(token_index=0, amount=1)
    with pytest.raises(ValueError):
        MintMeltEntry(token_index=17, amount=1)
    # amount in [1, 2**64).
    with pytest.raises(ValueError):
        MintMeltEntry(token_index=1, amount=0)
    with pytest.raises(ValueError):
        MintMeltEntry(token_index=1, amount=2 ** 64)


# --- wire format ------------------------------------------------------------

@pytest.mark.parametrize('header_cls,header_id,_deser', CASES)
def test_serialize_wire_format(header_cls: _HeaderCls, header_id: VertexHeaderId, _deser: _HeaderDeserializer) -> None:
    entries = [MintMeltEntry(token_index=1, amount=1000), MintMeltEntry(token_index=3, amount=2 ** 63)]
    wire = header_cls(entries=entries).serialize()
    # header_id(1) | num_entries(1) | (token_index(1) | amount(8 BE)) * n
    assert wire[:1] == header_id.value
    assert wire[1] == len(entries)
    assert len(wire) == 1 + 1 + len(entries) * 9


@pytest.mark.parametrize('header_cls,header_id,deser', CASES)
def test_framework_roundtrip(header_cls: _HeaderCls, header_id: VertexHeaderId, deser: _HeaderDeserializer) -> None:
    entries = [MintMeltEntry(token_index=2, amount=42), MintMeltEntry(token_index=5, amount=2 ** 63)]
    wire = header_cls(entries=entries).serialize()

    deserializer = Deserializer.build_bytes_deserializer(wire)
    parsed = deser(deserializer)
    assert deserializer.is_empty()
    assert parsed == entries

    # trailing bytes belong to the next header — not consumed.
    trailing = b'\xde\xad\xbe\xef'
    deserializer = Deserializer.build_bytes_deserializer(wire + trailing)
    parsed = deser(deserializer)
    assert parsed == entries
    assert bytes(deserializer.read_all()) == trailing

    # sighash is the full serialization (signature-bound).
    assert header_cls(entries=entries).get_sighash_bytes() == wire


@pytest.mark.parametrize('header_cls,header_id,deser', CASES)
def test_framework_rejects_malformed(
    header_cls: _HeaderCls,
    header_id: VertexHeaderId,
    deser: _HeaderDeserializer,
) -> None:
    good = header_cls(entries=[MintMeltEntry(token_index=1, amount=1)]).serialize()

    # wrong header id byte
    with pytest.raises(InvalidMintMeltHeaderError):
        deserialize_mint_header(Deserializer.build_bytes_deserializer(b'\x99' + good[1:]))

    # num_entries == 0 (at least one entry required)
    with pytest.raises(InvalidMintMeltHeaderError):
        deser(Deserializer.build_bytes_deserializer(header_id.value + b'\x00'))

    # num_entries exceeds the maximum
    with pytest.raises(InvalidMintMeltHeaderError):
        deser(Deserializer.build_bytes_deserializer(header_id.value + b'\x11'))

    # truncated entry bytes
    with pytest.raises(InvalidMintMeltHeaderError):
        deser(Deserializer.build_bytes_deserializer(good[:3]))


# --- feature gate -----------------------------------------------------------

def test_supported_headers_gated(settings_off: HathorSettings, settings_on: HathorSettings) -> None:
    supported_off = VertexParser.get_supported_headers(settings_off)
    supported_on = VertexParser.get_supported_headers(settings_on)
    for header_id in MINT_MELT_HEADER_IDS:
        assert header_id not in supported_off, f'{header_id!r} must be gated off'
        assert header_id in supported_on, f'{header_id!r} must be available when enabled'
    assert supported_on[VertexHeaderId.MINT_HEADER] is MintHeader
    assert supported_on[VertexHeaderId.MELT_HEADER] is MeltHeader


@pytest.mark.parametrize('header_id', MINT_MELT_HEADER_IDS)
def test_get_header_parser_gated(
    settings_off: HathorSettings,
    settings_on: HathorSettings,
    header_id: VertexHeaderId,
) -> None:
    with pytest.raises(ValueError, match='Header type not supported'):
        VertexParser.get_header_parser(header_id.value, settings_off)
    assert VertexParser.get_header_parser(header_id.value, settings_on) is not None


def test_allowed_headers_gated() -> None:
    """A REGULAR_TRANSACTION admits MintHeader/MeltHeader only when shielded is active."""
    verifier = VertexVerifier(reactor=Mock(), settings=get_global_settings(), feature_service=Mock())
    tx = Transaction()  # default version is REGULAR_TRANSACTION

    features_on = Features.all_enabled()
    features_off = dataclasses.replace(features_on, shielded_transactions=False)
    params_off = VerificationParams.for_mempool(best_block=Mock(), features=features_off)
    params_on = VerificationParams.for_mempool(best_block=Mock(), features=features_on)

    allowed_off = verifier.get_allowed_headers(tx, params_off)
    assert MintHeader not in allowed_off
    assert MeltHeader not in allowed_off

    allowed_on = verifier.get_allowed_headers(tx, params_on)
    assert MintHeader in allowed_on
    assert MeltHeader in allowed_on
