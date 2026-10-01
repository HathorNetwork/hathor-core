#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from types import SimpleNamespace

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.p2p.sync_v2.transaction_streaming_client import TransactionStreamingClient
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Block
from hathor_tests import unittest


class TestPartialBlockFeatures(unittest.TestCase):
    def test_verification_params_for_partial_block(self) -> None:
        # Feature states are only computed when the network defines a feature. The unittests
        # network defines none, which is why sync tests never reached this path.
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            max_signal_bits=4,
            default_threshold=3,
            features={
                Feature.NOP_FEATURE_1: Criteria(bit=0, start_height=4, timeout_height=12, version='0.0.0'),
            },
        )
        settings = self._settings.model_copy(update={'FEATURE_ACTIVATION': feature_settings})
        wallet = self._create_test_wallet(unlocked=True)
        manager = self.create_peer_from_builder(self.get_builder(settings).set_wallet(wallet))
        add_new_blocks(manager, 6, advance_clock=15)

        # A block whose transactions the syncing node does not have (a "partial block") is
        # deserialized but never saved and never goes through `on_new_block`, so its static
        # metadata is not initialized.
        new_blk = manager.generate_mining_block()
        partial_blk = Block.create_from_struct(bytes(new_blk), storage=manager.tx_storage)
        assert not manager.tx_storage.transaction_exists(partial_blk.hash)
        with self.assertRaises(AssertionError):
            partial_blk.static_metadata

        client = SimpleNamespace(protocol=SimpleNamespace(node=manager), tx_storage=manager.tx_storage)
        params = TransactionStreamingClient._make_verification_params(client, partial_blk)  # type: ignore[arg-type]

        # Restrictive features stay disabled for basic validation during sync.
        self.assertFalse(params.features.count_checkdatasig_op)
        self.assertFalse(params.features.restrict_dup_actions)
