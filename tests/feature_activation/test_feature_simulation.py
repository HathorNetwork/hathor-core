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

import pytest

from hathor.builder import Builder
from hathor.conf.get_settings import get_global_settings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.resources.feature import FeatureResource
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.simulator import FakeConnection
from hathor.simulator.utils import add_new_blocks
from hathor.transaction.exceptions import BlockMustSignalError
from hathor.util import not_none
from tests import unittest
from tests.resources.base_resource import StubSite
from tests.simulation.base import SimulatorTestCase
from tests.utils import HAS_ROCKSDB


class BaseFeatureSimulationTest(SimulatorTestCase):
    def get_simulator_builder(self) -> Builder:
        """Return a pre-configured builder to be used in tests."""
        raise NotImplementedError

    @staticmethod
    def _get_result(web_client: StubSite) -> dict[str, Any]:
        """Returns the feature activation api response."""
        response = web_client.get('feature')
        result: dict[str, Any] = response.result.json_value()

        del result['block_hash']  # we don't assert the block hash because it's not always the same

        return result

    def test_feature(self) -> None:
        """
        Tests that a feature goes through all possible states in the correct block heights.
        """
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

        settings = get_global_settings()._replace(FEATURE_ACTIVATION=feature_settings)
        builder = self.get_simulator_builder().set_settings(settings)
        artifacts = self.simulator.create_artifacts(builder)
        manager = artifacts.manager

        feature_resource = FeatureResource(settings=settings, tx_storage=artifacts.tx_storage)
        web_client = StubSite(feature_resource)

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at the beginning, the feature is DEFINED:
        add_new_blocks(manager, 10)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at block 19, the feature is DEFINED, just before becoming STARTED:
        add_new_blocks(manager, 9)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at block 20, the feature becomes STARTED:
        add_new_blocks(manager, 1)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

        # at block 55, the feature is STARTED, just before becoming MUST_SIGNAL:
        add_new_blocks(manager, 35)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

        # at block 56, the feature becomes MUST_SIGNAL:
        add_new_blocks(manager, 1)
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

        assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        add_new_blocks(manager, 1, signal_bits=0b1)

        # if we try to propagate a non-signaling block, it is not accepted
        non_signaling_block = manager.generate_mining_block()
        manager.cpu_mining_service.resolve(non_signaling_block)
        non_signaling_block.signal_bits = 0b10
        non_signaling_block.init_static_metadata_from_storage(settings, manager.tx_storage)

        with pytest.raises(BlockMustSignalError):
            manager.verification_service.verify(non_signaling_block)

        assert not manager.propagate_tx(non_signaling_block)

        # at block 59, the feature is MUST_SIGNAL, just before becoming LOCKED_IN:
        add_new_blocks(manager, num_blocks=2, signal_bits=0b1)
        self.simulator.run(60)
        result = self._get_result(web_client)
        assert result == dict(
            block_height=59,
            features=[
                dict(
                    name='NOP_FEATURE_1',
                    state='MUST_SIGNAL',
                    acceptance=0.75,
                    threshold=0.75,
                    start_height=20,
                    timeout_height=60,
                    minimum_activation_height=72,
                    lock_in_on_timeout=True,
                    version='0.0.0'
                )
            ]
        )

        assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at block 60, the feature becomes LOCKED_IN:
        add_new_blocks(manager, 1)
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

        assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at block 71, the feature is LOCKED_IN, just before becoming ACTIVE:
        add_new_blocks(manager, 11)
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

        assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at block 72, the feature becomes ACTIVE, forever:
        add_new_blocks(manager, 1)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == []

    def test_reorg(self) -> None:
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

        settings = get_global_settings()._replace(FEATURE_ACTIVATION=feature_settings)
        builder = self.get_simulator_builder().set_settings(settings)
        artifacts = self.simulator.create_artifacts(builder)
        manager = artifacts.manager

        feature_resource = FeatureResource(settings=settings, tx_storage=artifacts.tx_storage)
        web_client = StubSite(feature_resource)

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at the beginning, the feature is DEFINED:
        self.simulator.run(60)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # at block 4, the feature becomes STARTED with 0% acceptance
        add_new_blocks(manager, 4)
        self.simulator.run(60)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

        # at block 7, acceptance is 25% (we're signaling 1 block out of 4)
        add_new_blocks(manager, 2)
        add_new_blocks(manager, 1, signal_bits=0b10)
        self.simulator.run(60)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

        # at block 11, acceptance is 75% (we're signaling 3 blocks out of 4),
        # so the feature will be locked-in in the next block
        add_new_blocks(manager, 1)
        add_new_blocks(manager, 3, signal_bits=0b10)
        self.simulator.run(60)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

        # at block 12, the feature is locked-in
        add_new_blocks(manager, 1)
        self.simulator.run(60)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

        # at block 16, the feature is activated
        add_new_blocks(manager, 4)
        self.simulator.run(60)
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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == []

        # We then create a new manager with one more block (17 vs 16), so its blockchain wins when
        # both managers are connected. This causes a reorg and the feature goes back to the STARTED state.
        builder2 = self.get_simulator_builder().set_settings(settings)
        artifacts2 = self.simulator.create_artifacts(builder2)
        manager2 = artifacts2.manager

        add_new_blocks(manager2, 17)
        self.simulator.run(60)

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

        assert artifacts.bit_signaling_service.get_support_features() == []
        assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]


class BaseMemoryStorageFeatureSimulationTest(BaseFeatureSimulationTest):
    def get_simulator_builder(self) -> Builder:
        return self.simulator.get_default_builder()


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class BaseRocksDBStorageFeatureSimulationTest(BaseFeatureSimulationTest):
    def get_rocksdb_directory(self) -> str:
        import tempfile
        tmp_dir = tempfile.mkdtemp()
        self.tmpdirs.append(tmp_dir)
        return tmp_dir

    def get_simulator_builder_from_dir(self, rocksdb_directory: str) -> Builder:
        return self.simulator.get_default_builder() \
            .use_rocksdb(path=rocksdb_directory) \
            .disable_full_verification()

    def get_simulator_builder(self) -> Builder:
        rocksdb_directory = self.get_rocksdb_directory()
        return self.get_simulator_builder_from_dir(rocksdb_directory)

    def test_feature_from_existing_storage(self) -> None:
        """
        Tests that feature states are correctly retrieved from an existing storage, so no recalculation is required.
        """
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

        settings = get_global_settings()._replace(FEATURE_ACTIVATION=feature_settings)
        rocksdb_dir = self.get_rocksdb_directory()
        builder1 = self.get_simulator_builder_from_dir(rocksdb_dir).set_settings(settings)
        artifacts1 = self.simulator.create_artifacts(builder1)
        manager1 = artifacts1.manager

        feature_resource = FeatureResource(settings=settings, tx_storage=artifacts1.tx_storage)
        web_client = StubSite(feature_resource)

        assert artifacts1.tx_storage.get_vertices_count() == 3  # genesis vertices in the storage

        # we add 64 blocks so the feature becomes active. It would be active by timeout anyway,
        # we just set signal bits to conform with the MUST_SIGNAL phase.
        add_new_blocks(manager1, 64, signal_bits=0b1)
        self.simulator.run(60)
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
        assert artifacts1.tx_storage.get_vertices_count() == 67

        manager1.stop()
        not_none(artifacts1.rocksdb_storage).close()

        # new builder is created with the same storage from the previous manager
        builder2 = self.get_simulator_builder_from_dir(rocksdb_dir).set_settings(settings)
        artifacts2 = self.simulator.create_artifacts(builder2)

        feature_resource = FeatureResource(settings=settings, tx_storage=artifacts2.tx_storage)
        web_client = StubSite(feature_resource)

        # the new storage starts populated
        assert artifacts2.tx_storage.get_vertices_count() == 67
        self.simulator.run(60)

        result = self._get_result(web_client)

        # the result should be the same as before
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
        assert artifacts2.tx_storage.get_vertices_count() == 67


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
