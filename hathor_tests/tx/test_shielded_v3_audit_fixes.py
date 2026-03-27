# Copyright 2025 Hathor Labs
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

"""Regression tests for shielded outputs.

Streaming client must allow shielded transactions during sync.
All callers of for_mempool must pass explicit features.
is_shielded_output must not return True for out-of-range indices.
"""

import inspect
import textwrap
from typing import Any, Callable
from unittest.mock import MagicMock

from hathor.transaction.base_transaction import BaseTransaction


def _method_source_contains(method: Callable[..., Any], text: str) -> bool:
    """Return True if the method source contains the given text."""
    source = textwrap.dedent(inspect.getsource(method))
    return text in source


class TestStreamingClientFeatureGate:
    """Streaming client defaults to shielded_transactions=False.

    During sync, the node processes blocks at different heights — some before feature
    activation and some after.  Defaulting to False is safe because shielded txs cannot
    exist before the feature is activated.  Full validation will compute the correct
    value anyway.
    """

    def test_streaming_client_defaults_shielded_false(self) -> None:
        """The streaming client VerificationParams should default shielded_transactions=False."""
        from hathor.p2p.sync_v2.transaction_streaming_client import TransactionStreamingClient

        source = textwrap.dedent(inspect.getsource(TransactionStreamingClient.__init__))
        assert 'shielded_transactions=False' in source, \
            'Streaming client should default shielded_transactions=False'


class TestMempoolCallerFeatures:
    """All callers of for_mempool must pass explicit features (via all_enabled or from_vertex)."""

    def test_create_tx_passes_features(self) -> None:
        from hathor.transaction.resources.create_tx import CreateTxResource
        method = CreateTxResource._verify_unsigned_skip_pow
        assert _method_source_contains(method, 'Features.all_enabled()'), \
            'Regression: CreateTxResource._verify_unsigned_skip_pow must use Features.all_enabled()'
        assert _method_source_contains(method, 'for_mempool('), \
            'Regression: CreateTxResource._verify_unsigned_skip_pow must call for_mempool'

    def test_wallet_send_tokens_passes_features(self) -> None:
        from hathor.wallet.resources.send_tokens import SendTokensResource
        method = SendTokensResource._render_POST_thread
        assert _method_source_contains(method, 'Features.all_enabled()'), \
            'Regression: SendTokensResource._render_POST_thread must use Features.all_enabled()'
        assert _method_source_contains(method, 'for_mempool('), \
            'Regression: SendTokensResource._render_POST_thread must call for_mempool'

    def test_thin_wallet_stratum_verify_passes_features(self) -> None:
        from hathor.wallet.resources.thin_wallet.send_tokens import SendTokensResource
        method = SendTokensResource._stratum_thread_verify
        assert _method_source_contains(method, 'Features.all_enabled()'), \
            'Regression: thin_wallet._stratum_thread_verify must use Features.all_enabled()'
        assert _method_source_contains(method, 'for_mempool('), \
            'Regression: thin_wallet._stratum_thread_verify must call for_mempool'

    def test_thin_wallet_render_post_passes_features(self) -> None:
        from hathor.wallet.resources.thin_wallet.send_tokens import SendTokensResource
        method = SendTokensResource._render_POST_thread
        assert _method_source_contains(method, 'Features.all_enabled()'), \
            'Regression: thin_wallet._render_POST_thread must use Features.all_enabled()'
        assert _method_source_contains(method, 'for_mempool('), \
            'Regression: thin_wallet._render_POST_thread must call for_mempool'

    def test_consensus_opcodes_v2_rule(self) -> None:
        from hathor.consensus.consensus import ConsensusAlgorithm
        method = ConsensusAlgorithm._opcodes_v2_activation_rule
        assert _method_source_contains(method, 'OpcodesVersion.V2'), \
            'Regression: ConsensusAlgorithm._opcodes_v2_activation_rule must use OpcodesVersion.V2'


class TestIsShieldedOutputBounds:
    """is_shielded_output must check upper bound."""

    def test_returns_false_when_no_shielded_outputs(self) -> None:
        """Out-of-range index must return False when there are no shielded outputs."""
        tx = MagicMock(spec=BaseTransaction)
        tx.outputs = [MagicMock(), MagicMock()]
        tx.shielded_outputs = []
        tx.is_shielded_output = BaseTransaction.is_shielded_output.__get__(tx)

        assert tx.is_shielded_output(2) is False
        assert tx.is_shielded_output(100) is False

    def test_returns_true_for_valid_shielded_index(self) -> None:
        """Index in the shielded range must return True."""
        tx = MagicMock(spec=BaseTransaction)
        tx.outputs = [MagicMock(), MagicMock()]
        tx.shielded_outputs = [MagicMock()]
        tx.is_shielded_output = BaseTransaction.is_shielded_output.__get__(tx)

        assert tx.is_shielded_output(2) is True

    def test_returns_false_for_standard_index(self) -> None:
        """Standard output index must return False."""
        tx = MagicMock(spec=BaseTransaction)
        tx.outputs = [MagicMock(), MagicMock()]
        tx.shielded_outputs = [MagicMock()]
        tx.is_shielded_output = BaseTransaction.is_shielded_output.__get__(tx)

        assert tx.is_shielded_output(0) is False
        assert tx.is_shielded_output(1) is False

    def test_returns_false_beyond_shielded_range(self) -> None:
        """Index beyond both standard and shielded outputs must return False."""
        tx = MagicMock(spec=BaseTransaction)
        tx.outputs = [MagicMock(), MagicMock()]
        tx.shielded_outputs = [MagicMock()]
        tx.is_shielded_output = BaseTransaction.is_shielded_output.__get__(tx)

        # 2 standard + 1 shielded = valid range 0..2, index 3 is out of range
        assert tx.is_shielded_output(3) is False
        assert tx.is_shielded_output(100) is False
