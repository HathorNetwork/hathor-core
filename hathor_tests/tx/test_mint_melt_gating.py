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

"""Feature-gating of the MintHeader / MeltHeader at the parser and verifier layers.

Wire format and the verification rules (M1–M4) are covered in test_mint_melt.py;
here we only assert the ENABLE_SHIELDED_TRANSACTIONS gate for header parsing and
the allowed-headers set, including that a TokenCreationTransaction admits a
MintHeader but never a MeltHeader.
"""

import dataclasses
from unittest.mock import Mock

import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import FeatureSetting, HathorSettings
from hathor.feature_activation.utils import Features
from hathor.transaction import Transaction
from hathor.transaction.headers import MeltHeader, MintHeader, VertexHeaderId
from hathor.transaction.vertex_parser._vertex_parser import VertexParser
from hathor.verification.verification_params import VerificationParams
from hathor.verification.vertex_verifier import VertexVerifier

MINT_MELT_HEADER_IDS = [VertexHeaderId.MINT_HEADER, VertexHeaderId.MELT_HEADER]


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


def test_tct_admits_mint_header_but_not_melt_header() -> None:
    """A TOKEN_CREATION_TRANSACTION mints its new token (MintHeader) but never melts (no MeltHeader)."""
    from hathor.transaction.token_creation_tx import TokenCreationTransaction

    verifier = VertexVerifier(reactor=Mock(), settings=get_global_settings(), feature_service=Mock())
    tct = TokenCreationTransaction()
    params_on = VerificationParams.for_mempool(best_block=Mock(), features=Features.all_enabled())

    allowed = verifier.get_allowed_headers(tct, params_on)
    assert MintHeader in allowed
    assert MeltHeader not in allowed
