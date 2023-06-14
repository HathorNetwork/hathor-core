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

from hathor.feature_activation import feature_service
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.resources.feature import FeatureResource
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.simulator.trigger import StopAfterNMinedBlocks
from tests import unittest
from tests.resources.base_resource import StubSite
from tests.simulation.base import SimulatorTestCase

_FEATURE_SETTINGS = FeatureSettings(
    evaluation_interval=4,
    max_signal_bits=4,
    default_threshold=3,
    features={
        Feature.NOP_FEATURE_1: Criteria(
            bit=0,
            start_height=20,
            timeout_height=60,
            activate_on_timeout=True,
            version='0.0.0'
        )
    }
)


class BaseTestFeatureSimulation(SimulatorTestCase):
    def setUp(self):
        super().setUp()
        artifacts = self.simulator.create_artifacts()
        manager = artifacts.manager
        manager.allow_mining_without_peers()

        self.feature_service = artifacts.feature_service
        self.feature_service._feature_settings = _FEATURE_SETTINGS
        feature_resource = FeatureResource(
            feature_settings=_FEATURE_SETTINGS,
            feature_service=self.feature_service,
            tx_storage=manager.tx_storage
        )
        self.web_client = StubSite(feature_resource)

        self.miner = self.simulator.create_miner(manager, hashpower=1e6)
        self.miner.start()

    def _get_result_after(self, *, n_blocks: int) -> dict[str, Any]:
        trigger = StopAfterNMinedBlocks(self.miner, quantity=n_blocks)
        self.simulator.run(7200, trigger=trigger)

        response = self.web_client.get('feature')
        result = response.result.json_value()

        del result['block_hash']  # we don't assert the block hash because it's not always the same

        return result

    def test_feature(self):
        """
        Test that a feature goes through all possible states in the correct block heights, and also assert internal
        method call counts to make sure we're executing it in the most performatic way.
        """
        get_ancestor_iteratively_mock = Mock(wraps=feature_service._get_ancestor_iteratively)

        with patch.object(feature_service, '_get_ancestor_iteratively', get_ancestor_iteratively_mock):
            # at the beginning, the feature is DEFINED
            assert self._get_result_after(n_blocks=10) == dict(
                block_height=10,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='DEFINED',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=0,
                        activate_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            # no blocks are voided, so we only use the height index:
            assert get_ancestor_iteratively_mock.call_count == 0

            # at block 19, the feature is DEFINED, just before becoming STARTED
            assert self._get_result_after(n_blocks=9) == dict(
                block_height=19,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='DEFINED',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=0,
                        activate_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert get_ancestor_iteratively_mock.call_count == 0

            # at block 20, the feature becomes STARTED
            assert self._get_result_after(n_blocks=1) == dict(
                block_height=20,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='STARTED',
                        acceptance=0,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=0,
                        activate_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert get_ancestor_iteratively_mock.call_count == 0

            # at block 39, the feature is STARTED, just before becoming ACTIVE
            assert self._get_result_after(n_blocks=39) == dict(
                block_height=59,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='STARTED',
                        acceptance=0,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=0,
                        activate_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert get_ancestor_iteratively_mock.call_count == 0

            # at block 60, the feature becomes ACTIVE, forever
            assert self._get_result_after(n_blocks=1) == dict(
                block_height=60,
                features=[
                    dict(
                        name='NOP_FEATURE_1',
                        state='ACTIVE',
                        acceptance=None,
                        threshold=0.75,
                        start_height=20,
                        timeout_height=60,
                        minimum_activation_height=0,
                        activate_on_timeout=True,
                        version='0.0.0'
                    )
                ]
            )
            assert get_ancestor_iteratively_mock.call_count == 0


class SyncV1BaseTestFeatureSimulation(unittest.SyncV1Params, BaseTestFeatureSimulation):
    __test__ = True


class SyncV2BaseTestFeatureSimulation(unittest.SyncV2Params, BaseTestFeatureSimulation):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeBaseTestFeatureSimulation(unittest.SyncBridgeParams, SyncV2BaseTestFeatureSimulation):
    __test__ = True
