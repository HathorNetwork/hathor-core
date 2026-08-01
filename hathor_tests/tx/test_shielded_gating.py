# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Gating tests: the shielded-outputs machinery must be inert while
``ENABLE_SHIELDED_TRANSACTIONS`` is OFF.

These are pure parsing/gating checks at three layers — the vertex parser
(``get_supported_headers`` / ``get_header_parser``), the header deserialization
path (``deserialize_headers``), and the verifier admission set
(``VertexVerifier.get_allowed_headers``). None of them construct shielded
commitments, so they do not require the native crypto library.
"""

import dataclasses
from unittest.mock import Mock

import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import FeatureSetting, HathorSettings
from hathor.feature_activation.utils import Features
from hathor.serialization import Deserializer
from hathor.transaction import Transaction
from hathor.transaction.headers import ShieldedOutputsHeader, UnshieldBalanceHeader, VertexHeaderId
from hathor.transaction.vertex_parser._headers import deserialize_headers
from hathor.transaction.vertex_parser._vertex_parser import VertexParser
from hathor.verification.verification_params import VerificationParams
from hathor.verification.vertex_verifier import VertexVerifier

SHIELDED_HEADER_IDS = [
    VertexHeaderId.SHIELDED_OUTPUTS_HEADER,
    VertexHeaderId.UNSHIELD_BALANCE_HEADER,
]


@pytest.fixture
def settings_off() -> HathorSettings:
    """Default unittests settings — ENABLE_SHIELDED_TRANSACTIONS is disabled."""
    settings = get_global_settings()
    # Guard the premise of every test in this file.
    assert not settings.ENABLE_SHIELDED_TRANSACTIONS
    return settings


@pytest.fixture
def settings_on(settings_off: HathorSettings) -> HathorSettings:
    """Same settings but with ENABLE_SHIELDED_TRANSACTIONS enabled."""
    settings = settings_off.model_copy(update={'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED})
    assert settings.ENABLE_SHIELDED_TRANSACTIONS
    return settings


# --- parser layer: the supported-headers set (source of truth for the gate) ---

def test_supported_headers_excludes_shielded_when_disabled(
    settings_off: HathorSettings,
    settings_on: HathorSettings,
) -> None:
    supported_off = VertexParser.get_supported_headers(settings_off)
    supported_on = VertexParser.get_supported_headers(settings_on)
    for header_id in SHIELDED_HEADER_IDS:
        assert header_id not in supported_off, f'{header_id!r} must be gated off'
        assert header_id in supported_on, f'{header_id!r} must be available when enabled'
    assert supported_on[VertexHeaderId.SHIELDED_OUTPUTS_HEADER] is ShieldedOutputsHeader
    assert supported_on[VertexHeaderId.UNSHIELD_BALANCE_HEADER] is UnshieldBalanceHeader


@pytest.mark.parametrize('header_id', SHIELDED_HEADER_IDS)
def test_get_header_parser_rejects_shielded_when_disabled(
    settings_off: HathorSettings,
    settings_on: HathorSettings,
    header_id: VertexHeaderId,
) -> None:
    with pytest.raises(ValueError, match='Header type not supported'):
        VertexParser.get_header_parser(header_id.value, settings_off)
    # Sanity: when enabled it resolves to a header class instead of raising.
    assert VertexParser.get_header_parser(header_id.value, settings_on) is not None


# --- deserialization path: the real parse loop rejects the header byte when disabled ---

@pytest.mark.parametrize('header_id', SHIELDED_HEADER_IDS)
def test_deserialize_headers_rejects_shielded_when_disabled(
    settings_off: HathorSettings,
    header_id: VertexHeaderId,
) -> None:
    vertex = Transaction()
    deserializer = Deserializer.build_bytes_deserializer(header_id.value)
    with pytest.raises(ValueError, match='Header type not supported'):
        deserialize_headers(deserializer, vertex, settings_off)


# --- verifier layer: allowed-headers admission for a REGULAR_TRANSACTION ---

def test_allowed_headers_excludes_shielded_when_disabled() -> None:
    verifier = VertexVerifier(reactor=Mock(), settings=get_global_settings(), feature_service=Mock())
    tx = Transaction()  # default version is REGULAR_TRANSACTION

    features_on = Features.all_enabled()
    features_off = dataclasses.replace(features_on, shielded_transactions=False)
    params_off = VerificationParams(nc_block_root_id=None, features=features_off)
    params_on = VerificationParams(nc_block_root_id=None, features=features_on)

    allowed_off = verifier.get_allowed_headers(tx, params_off)
    assert ShieldedOutputsHeader not in allowed_off
    assert UnshieldBalanceHeader not in allowed_off

    allowed_on = verifier.get_allowed_headers(tx, params_on)
    assert ShieldedOutputsHeader in allowed_on
    assert UnshieldBalanceHeader in allowed_on
