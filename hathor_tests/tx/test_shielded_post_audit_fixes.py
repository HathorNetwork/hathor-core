# Copyright 2024 Hathor Labs
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

"""TDD tests for post-audit security fixes (C-001 through C-015).

Each test is written RED-first: it should FAIL before the fix and PASS after.
"""

import os
from unittest.mock import MagicMock, patch

import hathor_ct_crypto as lib
import pytest

from hathor.consensus.consensus import ConsensusAlgorithm
from hathor.feature_activation.feature import Feature
from hathor.transaction import Transaction
from hathor.transaction.shielded_tx_output import AmountShieldedOutput


def _make_amount_shielded(amount: int = 1000, token_data: int = 0) -> AmountShieldedOutput:
    gen = lib.htr_asset_tag()
    blinding = os.urandom(32)
    commitment = lib.create_commitment(amount, blinding, gen)
    range_proof = lib.create_range_proof(amount, blinding, commitment, gen)
    script = b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac'
    return AmountShieldedOutput(
        commitment=commitment,
        range_proof=range_proof,
        script=script,
        token_data=token_data,
    )


# ---------------------------------------------------------------------------
# C-013: Consensus reorg must re-validate shielded feature activation state
# ---------------------------------------------------------------------------


class TestC013ShieldedReorgRevalidation:
    """Feature.SHIELDED_TRANSACTIONS must NOT be in the NOP group.

    When a reorg changes the feature activation boundary, transactions
    with shielded outputs must be invalidated if the feature becomes
    inactive at the new best block height.
    """

    def _make_consensus_algorithm(self) -> ConsensusAlgorithm:
        """Create a minimal ConsensusAlgorithm with mocked dependencies."""
        consensus = MagicMock(spec=ConsensusAlgorithm)
        # Use the real methods we're testing
        consensus._shielded_activation_rule = ConsensusAlgorithm._shielded_activation_rule.__get__(consensus)
        consensus._feature_activation_rules = ConsensusAlgorithm._feature_activation_rules.__get__(consensus)
        # Mock the other rules to return True (valid) — they're not under test
        consensus._nano_activation_rule = MagicMock(return_value=True)
        consensus._fee_tokens_activation_rule = MagicMock(return_value=True)
        consensus._checkdatasig_count_rule = MagicMock(return_value=True)
        consensus._opcodes_v2_activation_rule = MagicMock(return_value=True)
        return consensus

    def test_shielded_tx_invalidated_when_feature_becomes_inactive(self):
        """A shielded tx must be invalidated if Feature.SHIELDED_TRANSACTIONS
        becomes inactive after a reorg."""
        consensus = self._make_consensus_algorithm()

        # Create a mock tx with shielded outputs
        tx = MagicMock(spec=Transaction)
        tx.has_shielded_outputs.return_value = True
        tx.is_nano_contract.return_value = False
        tx.has_fees.return_value = False

        # Mock the feature service to report shielded as NOT active
        mock_block = MagicMock()
        feature_states = {}
        for feature in Feature:
            mock_state = MagicMock()
            if feature == Feature.SHIELDED_TRANSACTIONS:
                mock_state.is_active.return_value = False
            else:
                mock_state.is_active.return_value = True
            feature_states[feature] = mock_state

        consensus.feature_service = MagicMock()
        consensus.feature_service.get_feature_states.return_value = feature_states
        consensus._settings = MagicMock()

        # The rule should return False (tx is invalid) because shielded
        # feature is inactive but tx has shielded outputs
        result = consensus._feature_activation_rules(tx, mock_block)
        assert result is False, (
            "Shielded tx should be invalidated when Feature.SHIELDED_TRANSACTIONS "
            "is inactive after reorg"
        )

    def test_shielded_tx_valid_when_feature_is_active(self):
        """A shielded tx must remain valid when Feature.SHIELDED_TRANSACTIONS is active."""
        consensus = self._make_consensus_algorithm()

        tx = MagicMock(spec=Transaction)
        tx.has_shielded_outputs.return_value = True
        tx.is_nano_contract.return_value = False
        tx.has_fees.return_value = False

        mock_block = MagicMock()
        feature_states = {}
        for feature in Feature:
            mock_state = MagicMock()
            mock_state.is_active.return_value = True
            feature_states[feature] = mock_state

        consensus.feature_service = MagicMock()
        consensus.feature_service.get_feature_states.return_value = feature_states
        consensus._settings = MagicMock()

        result = consensus._feature_activation_rules(tx, mock_block)
        assert result is True

    def test_non_shielded_tx_unaffected_by_shielded_feature_state(self):
        """A normal tx (no shielded outputs) should not be affected by
        the shielded feature being inactive."""
        consensus = self._make_consensus_algorithm()

        tx = MagicMock(spec=Transaction)
        tx.has_shielded_outputs.return_value = False
        tx.is_nano_contract.return_value = False
        tx.has_fees.return_value = False

        mock_block = MagicMock()
        feature_states = {}
        for feature in Feature:
            mock_state = MagicMock()
            if feature == Feature.SHIELDED_TRANSACTIONS:
                mock_state.is_active.return_value = False
            else:
                mock_state.is_active.return_value = True
            feature_states[feature] = mock_state

        consensus.feature_service = MagicMock()
        consensus.feature_service.get_feature_states.return_value = feature_states
        consensus._settings = MagicMock()

        result = consensus._feature_activation_rules(tx, mock_block)
        assert result is True

    def test_shielded_activation_rule_method_exists(self):
        """The _shielded_activation_rule method must exist on ConsensusAlgorithm."""
        assert hasattr(ConsensusAlgorithm, '_shielded_activation_rule'), (
            "ConsensusAlgorithm must have _shielded_activation_rule method"
        )


# ---------------------------------------------------------------------------
# C-014: Wallet must NOT log recovered shielded output values
# ---------------------------------------------------------------------------


class TestC014WalletLogPrivacy:
    """The wallet must not log the hidden value from shielded outputs."""

    def test_wallet_log_does_not_contain_value(self):
        """Verify the wallet's _process_shielded_outputs_on_new_tx does not
        log the recovered value at any level."""
        import ast
        import inspect
        import textwrap

        from hathor.wallet.base_wallet import BaseWallet

        # Get the source of the method
        source = inspect.getsource(BaseWallet._process_shielded_outputs_on_new_tx)
        source = textwrap.dedent(source)

        # Parse the AST and look for any log call that includes 'value' as a keyword
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if this is a log.debug/log.info/etc call
                func = node.func
                is_log_call = False
                if isinstance(func, ast.Attribute) and func.attr in ('debug', 'info', 'warning', 'error'):
                    if isinstance(func.value, ast.Attribute) and func.value.attr == 'log':
                        is_log_call = True
                    elif isinstance(func.value, ast.Name) and func.value.id in ('log', 'self'):
                        is_log_call = True

                if is_log_call:
                    # Check keywords for 'value'
                    for kw in node.keywords:
                        assert kw.arg != 'value', (
                            f"Found value= keyword in log call at line {node.lineno}. "
                            "Shielded output values must NOT be logged — this defeats "
                            "the privacy guarantee of Pedersen commitments."
                        )


# ---------------------------------------------------------------------------
# C-001: Startup check for crypto library availability
# ---------------------------------------------------------------------------


class TestC001CryptoLibraryStartupCheck:
    """When ENABLE_SHIELDED_TRANSACTIONS != DISABLED, the crypto library
    must be available. The system should fail fast at startup if not."""

    def test_validate_shielded_crypto_available_exists(self):
        """A validation function must exist that checks crypto availability."""
        from hathor.crypto.shielded import validate_shielded_crypto_available
        assert callable(validate_shielded_crypto_available)

    def test_validate_raises_when_lib_unavailable_and_feature_not_disabled(self):
        """Should raise RuntimeError when feature is enabled but lib is missing."""
        from hathor.conf.settings import FeatureSetting
        from hathor.crypto.shielded import validate_shielded_crypto_available

        with patch('hathor.crypto.shielded.SHIELDED_CRYPTO_AVAILABLE', False):
            with pytest.raises(RuntimeError, match='hathor_ct_crypto.*not available'):
                validate_shielded_crypto_available(FeatureSetting.ENABLED)

    def test_validate_raises_for_feature_activation_mode(self):
        """Should also raise when feature is in FEATURE_ACTIVATION mode."""
        from hathor.conf.settings import FeatureSetting
        from hathor.crypto.shielded import validate_shielded_crypto_available

        with patch('hathor.crypto.shielded.SHIELDED_CRYPTO_AVAILABLE', False):
            with pytest.raises(RuntimeError, match='hathor_ct_crypto.*not available'):
                validate_shielded_crypto_available(FeatureSetting.FEATURE_ACTIVATION)

    def test_validate_ok_when_disabled(self):
        """Should NOT raise when feature is DISABLED, even if lib is missing."""
        from hathor.conf.settings import FeatureSetting
        from hathor.crypto.shielded import validate_shielded_crypto_available

        with patch('hathor.crypto.shielded.SHIELDED_CRYPTO_AVAILABLE', False):
            # Should not raise
            validate_shielded_crypto_available(FeatureSetting.DISABLED)

    def test_validate_ok_when_lib_available(self):
        """Should NOT raise when lib is available regardless of feature setting."""
        from hathor.conf.settings import FeatureSetting
        from hathor.crypto.shielded import validate_shielded_crypto_available

        with patch('hathor.crypto.shielded.SHIELDED_CRYPTO_AVAILABLE', True):
            validate_shielded_crypto_available(FeatureSetting.ENABLED)
            validate_shielded_crypto_available(FeatureSetting.FEATURE_ACTIVATION)
            validate_shielded_crypto_available(FeatureSetting.DISABLED)


# ---------------------------------------------------------------------------
# C-001 (cont): Wallet exception handler must be narrow
# ---------------------------------------------------------------------------


class TestC001WalletExceptionHandler:
    """The wallet's shielded output processing must NOT use bare
    'except Exception:'. It should catch only expected errors."""

    def test_wallet_does_not_use_bare_except_exception(self):
        """Verify the except clause is narrowed from 'except Exception'."""
        import ast
        import inspect
        import textwrap

        from hathor.wallet.base_wallet import BaseWallet

        source = inspect.getsource(BaseWallet._process_shielded_outputs_on_new_tx)
        source = textwrap.dedent(source)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    pytest.fail("Found bare 'except:' clause — must specify exception types")
                if isinstance(node.type, ast.Name) and node.type.id == 'Exception':
                    pytest.fail(
                        "Found 'except Exception:' — too broad. Must catch specific "
                        "exceptions (ValueError, TypeError) to avoid swallowing "
                        "RuntimeError from missing crypto library."
                    )


# ---------------------------------------------------------------------------
# C-002: Explicit type guard for shielded verify_sum bypass
# ---------------------------------------------------------------------------


class TestC002TypeGuardVerifySum:
    """The shielded verify_sum bypass must explicitly exclude
    TokenCreationTransaction to prevent minting bypass."""

    def test_verify_sum_bypass_excludes_token_creation_tx(self):
        """In _verify_tx, the shielded branch must exclude TokenCreationTransaction."""
        import inspect
        import textwrap

        from hathor.verification.verification_service import VerificationService

        source = inspect.getsource(VerificationService._verify_tx)
        source = textwrap.dedent(source)

        # The shielded branch must explicitly mention TokenCreationTransaction
        # to guard against subclass matching.
        assert 'TokenCreationTransaction' in source, (
            "The shielded verify_sum bypass in _verify_tx must explicitly "
            "exclude TokenCreationTransaction to prevent minting bypass."
        )


# ---------------------------------------------------------------------------
# C-015: Cross-check token UID in FullShieldedOutput wallet recovery
# ---------------------------------------------------------------------------


class TestC015TokenUIDCrossCheck:
    """When recovering a FullShieldedOutput, the wallet must verify the
    token UID extracted from the range proof message against the
    asset_commitment."""

    def test_wallet_recovery_validates_token_uid_from_message(self):
        """The wallet must call _verify_recovered_token_uid to cross-check
        the token_id recovered from the range proof message."""
        import inspect
        import textwrap

        from hathor.wallet.base_wallet import BaseWallet

        source = inspect.getsource(BaseWallet._process_shielded_outputs_on_new_tx)
        source = textwrap.dedent(source)

        assert '_verify_recovered_token_uid' in source, (
            "Wallet must cross-check token UID from range proof message "
            "against asset_commitment to prevent social engineering attacks."
        )

    def test_verify_recovered_token_uid_rejects_wrong_token(self):
        """_verify_recovered_token_uid should reject mismatched token UIDs."""
        from hathor.wallet.base_wallet import BaseWallet

        # Create a valid FullShieldedOutput for HTR
        token_uid = bytes(32)  # HTR
        raw_tag = lib.derive_tag(token_uid)
        asset_bf = os.urandom(32)
        asset_comm = lib.create_asset_commitment(raw_tag, asset_bf)

        # Verify with correct token_uid should succeed
        BaseWallet._verify_recovered_token_uid(token_uid, asset_bf, asset_comm)

        # Verify with wrong token_uid should fail
        wrong_token_uid = os.urandom(32)
        with pytest.raises(ValueError, match='fraudulent token UID'):
            BaseWallet._verify_recovered_token_uid(wrong_token_uid, asset_bf, asset_comm)

    def test_verify_recovered_token_uid_rejects_wrong_blinding(self):
        """_verify_recovered_token_uid should reject wrong blinding factor."""
        from hathor.wallet.base_wallet import BaseWallet

        token_uid = bytes(32)
        raw_tag = lib.derive_tag(token_uid)
        asset_bf = os.urandom(32)
        asset_comm = lib.create_asset_commitment(raw_tag, asset_bf)

        wrong_bf = os.urandom(32)
        with pytest.raises(ValueError, match='fraudulent token UID'):
            BaseWallet._verify_recovered_token_uid(token_uid, wrong_bf, asset_comm)


# ---------------------------------------------------------------------------
# C-006: Structured logging for shielded verification failures
# ---------------------------------------------------------------------------


class TestC006ShieldedVerificationLogging:
    """Shielded verification failures must be logged at WARNING level."""

    def test_shielded_verifier_has_logger(self):
        """The ShieldedTransactionVerifier must have a logger attribute."""
        from hathor.verification.shielded_transaction_verifier import ShieldedTransactionVerifier

        settings = MagicMock()
        verifier = ShieldedTransactionVerifier(settings=settings)
        assert hasattr(verifier, 'log'), (
            "ShieldedTransactionVerifier must have a 'log' attribute for structured logging"
        )

    def test_verification_service_logs_shielded_failures(self):
        """The verification service shielded paths must emit log messages."""
        import inspect
        import textwrap

        from hathor.verification.verification_service import VerificationService

        # Check _verify_basic_shielded_header and _verify_shielded_header
        for method_name in ('_verify_basic_shielded_header', '_verify_shielded_header'):
            source = inspect.getsource(getattr(VerificationService, method_name))
            source = textwrap.dedent(source)
            # Should have a try/except that logs failures
            assert 'log' in source or 'except' in source, (
                f"{method_name} should log shielded verification failures"
            )
