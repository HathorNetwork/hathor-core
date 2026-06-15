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

from hathorlib.conf.settings import FeatureSetting

from hathor.simulator.utils import add_new_blocks, gen_new_tx
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class NodeIntegrationTestCase(unittest.TestCase):
    def _finality_manager(self, enabled: bool):
        settings = self._settings.model_copy(
            update={'ENABLE_TWO_TIER_FINALITY': FeatureSetting.ENABLED if enabled else FeatureSetting.DISABLED}
        )
        return self.create_peer('testnet', settings=settings)

    def test_service_not_built_when_disabled(self) -> None:
        manager = self._finality_manager(enabled=False)
        assert manager.finality_service is None
        assert manager.tx_storage.indexes.finality_certificate is None
        # The finality capability must not be advertised.
        assert self._settings.CAPABILITY_FINALITY not in manager.get_default_capabilities()

    def test_service_built_when_enabled(self) -> None:
        manager = self._finality_manager(enabled=True)
        assert manager.finality_service is not None
        # This node has no signer, so it is not a validator.
        assert manager.finality_service.is_validator is False
        assert self._settings.CAPABILITY_FINALITY in manager.get_default_capabilities()

    def test_uncertified_finality_tx_is_diverted_from_mempool(self) -> None:
        manager = self._finality_manager(enabled=True)
        add_new_blocks(manager, 3, advance_clock=15)
        add_blocks_unlock_reward(manager)
        address = manager.wallet.get_unused_address(mark_as_used=True)
        tx = gen_new_tx(manager, address, 100)

        # The node has no validator peers, so the submission cannot be forwarded anywhere: the
        # transaction must be kept out of the mempool (it is not certified) rather than admitted.
        result = manager.vertex_handler.on_new_relayed_vertex(tx)
        assert result is False
        assert not manager.tx_storage.transaction_exists(tx.hash)
