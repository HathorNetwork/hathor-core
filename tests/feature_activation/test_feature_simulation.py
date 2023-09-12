#  Copyright 2023 Hathor Labs
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

from typing import Any
from unittest.mock import Mock, patch

import pytest

from hathor.builder import Builder
from hathor.feature_activation import feature_service as feature_service_module
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.resources.feature import FeatureResource
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from hathor.transaction import Transaction
from tests import unittest
from tests.resources.base_resource import StubSite
from tests.simulation.base import SimulatorTestCase
from tests.utils import HAS_ROCKSDB, add_new_blocks


class BaseFeatureSimulationTest(SimulatorTestCase):
    builder: Builder

    @staticmethod
    def _get_result(web_client: StubSite) -> dict[str, Any]:
        """Returns the feature activation api response."""
        response = web_client.get('feature')
        result = response.result.json_value()

        del result['block_hash']  # we don't assert the block hash because it's not always the same

        return result

    @staticmethod
    def _get_state_mock_block_height_calls(get_state_mock: Mock) -> list[int]:
        """Returns the heights of blocks that get_state_mock was called with."""
        return [call.kwargs['block'].get_height() for call in get_state_mock.call_args_list]

    def test_feature(self) -> None:
        """
        Tests that a feature goes through all possible states in the correct block heights, and also assert internal
        method call counts and args to make sure we're executing it in the most performatic way.
        """
        artifacts = self.simulator.create_artifacts(self.builder)
        manager = artifacts.manager
        manager.allow_mining_without_peers()

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            max_signal_bits=4,
            default_threshold=3,
            features={
                Feature.NOP_FEATURE_1: Criteria(
                    bit=0,
                    start_height=20,
                    timeout_height=60,
                    minimum_activation_height=72,
                    lock_in_on_timeout=True,
                    version='0.0.0'
                )
            }
        )

        feature_service = FeatureService(
            feature_settings=feature_settings,
            avg_time_between_blocks=30,
            tx_storage=artifacts.tx_storage
        )
        feature_resource = FeatureResource(
            feature_settings=feature_settings,
            feature_service=feature_service,
            tx_storage=artifacts.tx_storage
        )
        web_client = StubSite(feature_resource)

        get_state_mock = Mock(wraps=feature_service.get_state)
        get_ancestor_iteratively_mock = Mock(wraps=feature_service_module._get_ancestor_iteratively)

        with (
            patch.object(FeatureService, 'get_state', get_state_mock),
            patch.object(feature_service_module, '_get_ancestor_iteratively', get_ancestor_iteratively_mock)
        ):
            # at the beginning, the feature is DEFINED:
            blocks = add_new_blocks(manager, 10)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=10,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='DEFINED',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            # so we query states all the way down to genesis:
            assert self._get_state_mock_block_height_calls(get_state_mock) == [10, 8, 4, 0]
            # no blocks are voided, so we only use the height index, and not get_ancestor_iteratively:
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 19, the feature is DEFINED, just before becoming STARTED:
            blocks = add_new_blocks(manager, 9)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=19,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='DEFINED',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            # so we query states from block 19 to 8, as it's cached:
            assert self._get_state_mock_block_height_calls(get_state_mock) == [19, 16, 12, 8]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 20, the feature becomes STARTED:
            blocks = add_new_blocks(manager, 1)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=20,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='STARTED',
                        acceptance=0,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert self._get_state_mock_block_height_calls(get_state_mock) == [20, 16]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 55, the feature is STARTED, just before becoming MUST_SIGNAL:
            blocks = add_new_blocks(manager, 35)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=55,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='STARTED',
                        acceptance=0,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert (
                self._get_state_mock_block_height_calls(get_state_mock) == [55, 52, 48, 44, 40, 36, 32, 28, 24, 20]
            )
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 56, the feature becomes MUST_SIGNAL:
            blocks = add_new_blocks(manager, 1)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=56,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='MUST_SIGNAL',
                        acceptance=0,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert self._get_state_mock_block_height_calls(get_state_mock) == [56, 52]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 59, the feature is MUST_SIGNAL, just before becoming LOCKED_IN:
            blocks = add_new_blocks(manager, 3)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=59,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='MUST_SIGNAL',
                        acceptance=0,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert (
                self._get_state_mock_block_height_calls(get_state_mock) == [59, 56]
            )
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 60, the feature becomes LOCKED_IN:
            blocks = add_new_blocks(manager, 1)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=60,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='LOCKED_IN',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert self._get_state_mock_block_height_calls(get_state_mock) == [60, 56]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 71, the feature is LOCKED_IN, just before becoming ACTIVE:
            blocks = add_new_blocks(manager, 11)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=71,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='LOCKED_IN',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert (
                self._get_state_mock_block_height_calls(get_state_mock) == [71, 68, 64, 60]
            )
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 72, the feature becomes ACTIVE, forever:
            blocks = add_new_blocks(manager, 1)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=72,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='ACTIVE',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert self._get_state_mock_block_height_calls(get_state_mock) == [72, 68]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 75, the feature is still not ACTIVE for transactions, just before becoming ACTIVE:
            blocks = add_new_blocks(manager, 3)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=75,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='ACTIVE',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert self._get_state_mock_block_height_calls(get_state_mock) == [75, 72]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert not feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

            # at block 76, the feature becomes ACTIVE for transactions, forever:
            blocks = add_new_blocks(manager, 1)
            self.simulator.run(60)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=76,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='ACTIVE',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=72,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert self._get_state_mock_block_height_calls(get_state_mock) == [76, 72]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert feature_service.is_feature_active_for_transaction(
                transaction=Transaction(timestamp=blocks[-1].timestamp + 1),
                feature=Feature.NOP_FEATURE_1
            )
            get_state_mock.reset_mock()

    @pytest.mark.xfail(reason='TODO: FIX')
    def test_reorg(self) -> None:
        artifacts = self.simulator.create_artifacts(self.builder)
        manager = artifacts.manager
        manager.allow_mining_without_peers()

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            max_signal_bits=4,
            default_threshold=3,
            features={
                Feature.NOP_FEATURE_1: Criteria(
                    bit=1,
                    start_height=4,
                    timeout_height=100,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            }
        )
        feature_service = FeatureService(
            feature_settings=feature_settings,
            avg_time_between_blocks=30,
            tx_storage=artifacts.tx_storage
        )
        feature_resource = FeatureResource(
            feature_settings=feature_settings,
            feature_service=feature_service,
            tx_storage=artifacts.tx_storage
        )
        web_client = StubSite(feature_resource)

        # 4 blocks per evaluation interval, and the genesis is skipped
        signal_bits = [
            0b0000, 0b0000, 0b0000,          # 0% acceptance
            0b0000, 0b0000, 0b0010, 0b0000,  # 25% acceptance
            0b0010, 0b0000, 0b0010, 0b0010,  # 75% acceptance
        ]

        miner = self.simulator.create_miner(manager, hashpower=1e6, signal_bits=signal_bits)
        miner.start()

        # at the beginning, the feature is DEFINED:
        trigger = StopAfterNMinedBlocks(miner, quantity=0)
        self.simulator.run(36000, trigger=trigger)
        result = self._get_result(web_client)
        assert result == dict(
            block_height=0,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='DEFINED',
                    acceptance=None,
                    threshold=0.75,
                    start_height=4,
                    timeout_height=100,
                    minimum_activation_height=0,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            ]
        )
        assert not feature_service.is_feature_active_for_transaction(
            transaction=Transaction(timestamp=manager.tx_storage.get_best_block().timestamp + 1),
            feature=Feature.NOP_FEATURE_1
        )

        # at block 4, the feature becomes STARTED with 0% acceptance
        trigger = StopAfterNMinedBlocks(miner, quantity=4)
        self.simulator.run(36000, trigger=trigger)
        result = self._get_result(web_client)
        assert result == dict(
            block_height=4,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='STARTED',
                    acceptance=0,
                    threshold=0.75,
                    start_height=4,
                    timeout_height=100,
                    minimum_activation_height=0,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            ]
        )

        # at block 7, acceptance was 25%
        trigger = StopAfterNMinedBlocks(miner, quantity=3)
        self.simulator.run(36000, trigger=trigger)
        result = self._get_result(web_client)
        assert result == dict(
            block_height=7,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='STARTED',
                    acceptance=0.25,
                    threshold=0.75,
                    start_height=4,
                    timeout_height=100,
                    minimum_activation_height=0,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            ]
        )
        assert not feature_service.is_feature_active_for_transaction(
            transaction=Transaction(timestamp=manager.tx_storage.get_best_block().timestamp + 1),
            feature=Feature.NOP_FEATURE_1
        )

        # at block 11, acceptance was 75%, so the feature will be locked-in in the next block
        trigger = StopAfterNMinedBlocks(miner, quantity=4)
        self.simulator.run(36000, trigger=trigger)
        result = self._get_result(web_client)
        assert result == dict(
            block_height=11,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='STARTED',
                    acceptance=0.75,
                    threshold=0.75,
                    start_height=4,
                    timeout_height=100,
                    minimum_activation_height=0,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            ]
        )
        assert not feature_service.is_feature_active_for_transaction(
            transaction=Transaction(timestamp=manager.tx_storage.get_best_block().timestamp + 1),
            feature=Feature.NOP_FEATURE_1
        )

        # at block 12, the feature is locked-in
        trigger = StopAfterNMinedBlocks(miner, quantity=1)
        self.simulator.run(36000, trigger=trigger)
        result = self._get_result(web_client)
        assert result == dict(
            block_height=12,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='LOCKED_IN',
                    acceptance=None,
                    threshold=0.75,
                    start_height=4,
                    timeout_height=100,
                    minimum_activation_height=0,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            ]
        )
        assert not feature_service.is_feature_active_for_transaction(
            transaction=Transaction(timestamp=manager.tx_storage.get_best_block().timestamp + 1),
            feature=Feature.NOP_FEATURE_1
        )

        # at block 16, the feature is activated
        trigger = StopAfterNMinedBlocks(miner, quantity=4)
        self.simulator.run(36000, trigger=trigger)
        result = self._get_result(web_client)
        assert result == dict(
            block_height=16,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='ACTIVE',
                    acceptance=None,
                    threshold=0.75,
                    start_height=4,
                    timeout_height=100,
                    minimum_activation_height=0,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            ]
        )
        assert not feature_service.is_feature_active_for_transaction(
            transaction=Transaction(timestamp=manager.tx_storage.get_best_block().timestamp + 1),
            feature=Feature.NOP_FEATURE_1
        )

        miner.stop()

        # We then create a new manager with a miner that mines one more block (17 vs 16), so its blockchain wins when
        # both managers are connected. This causes a reorg and the feature goes back to the STARTED state.
        manager2 = self.simulator.create_peer()
        manager2.allow_mining_without_peers()

        miner2 = self.simulator.create_miner(manager2, hashpower=1e6)

        miner2.start()
        trigger = StopAfterNMinedBlocks(miner2, quantity=17)
        self.simulator.run(36000, trigger=trigger)
        miner2.stop()

        connection = FakeConnection(manager, manager2)
        self.simulator.add_connection(connection)
        self.simulator.run(60)

        result = self._get_result(web_client)
        assert result == dict(
            block_height=17,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='STARTED',
                    acceptance=0,
                    threshold=0.75,
                    start_height=4,
                    timeout_height=100,
                    minimum_activation_height=0,
                    lock_in_on_timeout=False,
                    version='0.0.0'
                )
            ]
        )
        assert not feature_service.is_feature_active_for_transaction(
            transaction=Transaction(timestamp=manager.tx_storage.get_best_block().timestamp + 1),
            feature=Feature.NOP_FEATURE_1
        )


class BaseMemoryStorageFeatureSimulationTest(BaseFeatureSimulationTest):
    def setUp(self):
        super().setUp()
        self.builder = self.simulator.get_default_builder()


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class BaseRocksDBStorageFeatureSimulationTest(BaseFeatureSimulationTest):
    def setUp(self):
        super().setUp()
        import tempfile

        self.rocksdb_directory = tempfile.mkdtemp()
        self.tmpdirs.append(self.rocksdb_directory)

        self.builder = self.simulator.get_default_builder() \
            .use_rocksdb(path=self.rocksdb_directory) \
            .disable_full_verification()

    def test_feature_from_existing_storage(self) -> None:
        """
        Tests that feature states are correctly retrieved from an existing storage, so no recalculation is required.
        """
        artifacts1 = self.simulator.create_artifacts(self.builder)
        manager1 = artifacts1.manager
        manager1.allow_mining_without_peers()

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            max_signal_bits=4,
            default_threshold=3,
            features={
                Feature.NOP_FEATURE_1: Criteria(
                    bit=0,
                    start_height=20,
                    timeout_height=60,
                    lock_in_on_timeout=True,
                    version='0.0.0'
                )
            }
        )

        feature_service = FeatureService(
            feature_settings=feature_settings,
            avg_time_between_blocks=30,
            tx_storage=artifacts1.tx_storage
        )
        feature_resource = FeatureResource(
            feature_settings=feature_settings,
            feature_service=feature_service,
            tx_storage=artifacts1.tx_storage
        )
        web_client = StubSite(feature_resource)

        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()

        get_state_mock = Mock(wraps=feature_service.get_state)
        get_ancestor_iteratively_mock = Mock(wraps=feature_service_module._get_ancestor_iteratively)

        with (
            patch.object(FeatureService, 'get_state', get_state_mock),
            patch.object(feature_service_module, '_get_ancestor_iteratively', get_ancestor_iteratively_mock)
        ):
            assert artifacts1.tx_storage.get_vertices_count() == 3  # genesis vertices in the storage

            trigger = StopAfterNMinedBlocks(miner, quantity=64)
            self.simulator.run(36000, trigger=trigger)
            result = self._get_result(web_client)
            assert result == dict(
                block_height=64,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='ACTIVE',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=0,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            # feature states have to be calculated for all blocks in evaluation interval boundaries, as this is the
            # first run:
            assert self._get_state_mock_block_height_calls(get_state_mock) == list(range(64, -4, -4))
            # no blocks are voided, so we only use the height index:
            assert get_ancestor_iteratively_mock.call_count == 0
            assert artifacts1.tx_storage.get_vertices_count() == 67
            get_state_mock.reset_mock()

        miner.stop()
        manager1.stop()
        artifacts1.rocksdb_storage.close()

        builder = self.simulator.get_default_builder() \
            .use_rocksdb(path=self.rocksdb_directory) \
            .disable_full_verification()
        artifacts2 = self.simulator.create_artifacts(builder)

        # new feature_service is created with the same storage generated above
        feature_service = FeatureService(
            feature_settings=feature_settings,
            avg_time_between_blocks=30,
            tx_storage=artifacts2.tx_storage
        )
        feature_resource = FeatureResource(
            feature_settings=feature_settings,
            feature_service=feature_service,
            tx_storage=artifacts2.tx_storage
        )
        web_client = StubSite(feature_resource)

        get_state_mock = Mock(wraps=feature_service.get_state)
        get_ancestor_iteratively_mock = Mock(wraps=feature_service_module._get_ancestor_iteratively)

        with (
            patch.object(FeatureService, 'get_state', get_state_mock),
            patch.object(feature_service_module, '_get_ancestor_iteratively', get_ancestor_iteratively_mock)
        ):
            # the new storage starts populated
            assert artifacts2.tx_storage.get_vertices_count() == 67
            self.simulator.run(3600)

            result = self._get_result(web_client)

            assert result == dict(
                block_height=64,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='ACTIVE',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=0,
                        lock_in_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            # features states are not queried for previous blocks, as they have it cached:
            assert self._get_state_mock_block_height_calls(get_state_mock) == [64]
            assert get_ancestor_iteratively_mock.call_count == 0
            assert artifacts2.tx_storage.get_vertices_count() == 67
            get_state_mock.reset_mock()


class SyncV1MemoryStorageFeatureSimulationTest(unittest.SyncV1Params, BaseMemoryStorageFeatureSimulationTest):
    __test__ = True


class SyncV2MemoryStorageFeatureSimulationTest(unittest.SyncV2Params, BaseMemoryStorageFeatureSimulationTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeMemoryStorageFeatureSimulationTest(unittest.SyncBridgeParams, BaseMemoryStorageFeatureSimulationTest):
    __test__ = True


class SyncV1RocksDBStorageFeatureSimulationTest(unittest.SyncV1Params, BaseRocksDBStorageFeatureSimulationTest):
    __test__ = True


class SyncV2RocksDBStorageFeatureSimulationTest(unittest.SyncV2Params, BaseRocksDBStorageFeatureSimulationTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeRocksDBStorageFeatureSimulationTest(
    unittest.SyncBridgeParams,
    BaseRocksDBStorageFeatureSimulationTest
):
    __test__ = True
