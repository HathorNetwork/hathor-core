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

from unittest.mock import Mock

from hathor.builder import Builder
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.simulator.utils import add_new_block, add_new_blocks, gen_new_tx
from hathor.transaction import Block
from tests import unittest
from tests.simulation.base import SimulatorTestCase


class BaseConsensusTestCase(SimulatorTestCase):
    __test = False

    def _get_builder(self) -> Builder:
        feature_service = Mock(spec_set=FeatureService)

        def is_feature_active_for_block(*, block: Block, feature: Feature) -> bool:
            assert feature is Feature.PARENT_BLOCK_FOR_TRANSACTIONS
            return True

        feature_service.is_feature_active_for_block = Mock(side_effect=is_feature_active_for_block)
        feature_service.get_bits_description = Mock(return_value={})
        builder = self.simulator.get_default_builder().set_feature_service(feature_service)
        return builder

    def test_tx_confirming_voided_block(self) -> None:
        builder = self._get_builder()
        artifacts = self.simulator.create_artifacts(builder)
        manager = artifacts.manager
        assert manager.wallet is not None
        address = manager.wallet.get_unused_address(mark_as_used=False)

        blocks = add_new_blocks(manager, self._settings.REWARD_SPEND_MIN_BLOCKS + 1)
        fork_block = blocks[5]
        parent_block = fork_block.parents[0]
        voided_block = add_new_block(manager, parent_block_hash=parent_block)
        assert voided_block.hash is not None
        self.simulator.run(60)

        tx = gen_new_tx(manager, address, 1000)
        tx.parents = [voided_block.hash, *tx.parents]
        tx.weight = manager.daa.minimum_tx_weight(tx)
        tx.update_hash()
        assert tx.hash is not None

        assert manager.propagate_tx(tx, fails_silently=False)
        self.simulator.run(60)

        tx_from_storage = manager.tx_storage.get_transaction(tx.hash)
        tx_from_storage_meta = tx_from_storage.get_metadata()

        block_from_storage = manager.tx_storage.get_transaction(voided_block.hash)
        block_from_storage_meta = block_from_storage.get_metadata()

        assert voided_block.hash in tx_from_storage_meta.voided_by, 'tx should be voided by block'
        assert voided_block.hash in tx_from_storage.parents, 'block should be in tx parents'
        assert block_from_storage_meta.voided_by, 'block should be voided'
        assert tx.hash in block_from_storage_meta.children, 'tx should be in block children'

    def test_tx_confirming_valid_block_that_becomes_voided(self) -> None:
        builder = self._get_builder()
        artifacts = self.simulator.create_artifacts(builder)
        manager = artifacts.manager
        assert manager.wallet is not None
        address = manager.wallet.get_unused_address(mark_as_used=False)

        *_, block = add_new_blocks(manager, self._settings.REWARD_SPEND_MIN_BLOCKS + 1)
        assert block.hash is not None
        self.simulator.run(60)

        tx = gen_new_tx(manager, address, 1000)
        tx.parents = [block.hash, *tx.parents]
        tx.weight = manager.daa.minimum_tx_weight(tx)
        tx.update_hash()
        assert tx.hash is not None

        assert manager.propagate_tx(tx, fails_silently=False)
        self.simulator.run(60)

        tx_from_storage = manager.tx_storage.get_transaction(tx.hash)
        tx_from_storage_meta = tx_from_storage.get_metadata()

        block_from_storage = manager.tx_storage.get_transaction(block.hash)
        block_from_storage_meta = block_from_storage.get_metadata()

        assert not tx_from_storage_meta.voided_by, 'tx should not be voided'
        assert block.hash in tx_from_storage.parents, 'block should be in tx parents'
        assert not block_from_storage_meta.voided_by, 'block should not be voided'
        assert tx.hash in block_from_storage_meta.children, 'tx should be in block children'

        reorg_block = manager.generate_mining_block()
        reorg_block.parents = block.parents
        reorg_block.weight = block.weight + 1
        manager.cpu_mining_service.resolve(reorg_block)
        assert reorg_block.hash is not None
        assert manager.propagate_tx(reorg_block, fails_silently=False)
        self.simulator.run(60)

        tx_from_storage = manager.tx_storage.get_transaction(tx.hash)
        tx_from_storage_meta = tx_from_storage.get_metadata()

        block_from_storage = manager.tx_storage.get_transaction(block.hash)
        block_from_storage_meta = block_from_storage.get_metadata()

        reorg_block_from_storage = manager.tx_storage.get_transaction(reorg_block.hash)
        reorg_block_from_storage_meta = reorg_block_from_storage.get_metadata()

        assert not reorg_block_from_storage_meta.voided_by, 'reorg block should not be voided'
        assert block_from_storage_meta.voided_by, 'block should be voided'
        assert block.hash in tx_from_storage_meta.voided_by, 'tx should be voided by block'


class SyncV1ConsensusTestCase(unittest.SyncV1Params, BaseConsensusTestCase):
    __test__ = True


class SyncV2ConsensusTestCase(unittest.SyncV2Params, BaseConsensusTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeConsensusTestCase(unittest.SyncBridgeParams, SyncV2ConsensusTestCase):
    pass
