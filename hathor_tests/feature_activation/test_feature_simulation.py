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
from hathor.conf.get_settings import get_global_settings
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.resources.feature import FeatureResource
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.simulator import FakeConnection
from hathor.simulator.utils import add_new_blocks, gen_new_tx
from hathor.transaction.exceptions import BlockMustSignalError
from hathor.util import not_none
from hathor_tests.resources.base_resource import StubSite
from hathor_tests.simulation.base import SimulatorTestCase


class BaseFeatureSimulationTest(SimulatorTestCase):
    __test__ = False

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

    @staticmethod
    def _calculate_new_state_mock_block_height_calls(calculate_new_state_mock: Mock) -> list[int]:
        """Return the heights of blocks that calculate_new_state_mock was called with."""
        return [call.kwargs['boundary_block'].get_height() for call in calculate_new_state_mock.call_args_list]

    def test_feature(self) -> None:
        """
        Tests that a feature goes through all possible states in the correct block heights, and also assert internal
        method calls to make sure we're executing it in the intended, most performatic way.
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

        settings = get_global_settings()._replace(FEATURE_ACTIVATION=feature_settings, REWARD_SPEND_MIN_BLOCKS=0)
        self.simulator.settings = settings
        builder = self.get_simulator_builder().set_settings(settings)
        artifacts = self.simulator.create_artifacts(builder)
        feature_service = artifacts.feature_service
        manager = artifacts.manager
        assert manager.wallet is not None
        address = manager.wallet.get_unused_address(mark_as_used=False)

        feature_resource = FeatureResource(
            settings=settings,
            feature_service=feature_service,
            tx_storage=artifacts.tx_storage
        )
        web_client = StubSite(feature_resource)

        calculate_new_state_mock = Mock(wraps=feature_service._calculate_new_state)
        get_ancestor_iteratively_mock = Mock(wraps=feature_service._get_ancestor_iteratively)

        with (
            patch.object(FeatureService, '_calculate_new_state', calculate_new_state_mock),
            patch.object(FeatureService, '_get_ancestor_iteratively', get_ancestor_iteratively_mock),
        ):
            assert artifacts.bit_signaling_service.get_support_features() == []
            assert artifacts.bit_signaling_service.get_not_support_features() == []

            # at the beginning, the feature is DEFINED:
            [*_, last_block] = add_new_blocks(manager, 10)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*10)
            tx.weight = 25
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            # so we calculate states all the way down to the first evaluation boundary (after genesis):
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 4
            # no blocks are voided, so we only use the height index, and not get_ancestor_iteratively:
            assert get_ancestor_iteratively_mock.call_count == 0
            calculate_new_state_mock.reset_mock()

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.DEFINED}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == []
            assert artifacts.bit_signaling_service.get_not_support_features() == []

            # at block 19, the feature is DEFINED, just before becoming STARTED:
            [*_, last_block] = add_new_blocks(manager, 9)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*19)
            tx.weight = 25
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            # so we calculate states down to block 12, as block 8's state is saved:
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 12
            assert get_ancestor_iteratively_mock.call_count == 0
            calculate_new_state_mock.reset_mock()

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.DEFINED}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == []
            assert artifacts.bit_signaling_service.get_not_support_features() == []

            # at block 20, the feature becomes STARTED:
            [*_, last_block] = add_new_blocks(manager, 1)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*20)
            tx.weight = 25
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 20
            assert get_ancestor_iteratively_mock.call_count == 0

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.STARTED}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == []
            assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

            # we add one block before resetting the mock, just to make sure block 20 gets a chance to be saved
            add_new_blocks(manager, 1)
            calculate_new_state_mock.reset_mock()

            # at block 55, the feature is STARTED, just before becoming MUST_SIGNAL:
            [*_, last_block] = add_new_blocks(manager, 34)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*55)
            tx.weight = 30
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 24
            assert get_ancestor_iteratively_mock.call_count == 0
            calculate_new_state_mock.reset_mock()

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.STARTED}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == []
            assert artifacts.bit_signaling_service.get_not_support_features() == [Feature.NOP_FEATURE_1]

            # at block 56, the feature becomes MUST_SIGNAL:
            [*_, last_block] = add_new_blocks(manager, 1)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*56)
            tx.weight = 30
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 56
            assert get_ancestor_iteratively_mock.call_count == 0

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.MUST_SIGNAL}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
            assert artifacts.bit_signaling_service.get_not_support_features() == []

            # we add one block before resetting the mock, just to make sure block 56 gets a chance to be saved
            add_new_blocks(manager, 1, signal_bits=0b1)
            calculate_new_state_mock.reset_mock()

            # if we try to propagate a non-signaling block, it is not accepted
            non_signaling_block = manager.generate_mining_block()
            manager.cpu_mining_service.resolve(non_signaling_block)
            non_signaling_block.signal_bits = 0b10
            non_signaling_block.init_static_metadata_from_storage(settings, manager.tx_storage)

            with pytest.raises(BlockMustSignalError):
                manager.verification_service.verify(non_signaling_block, self.get_verification_params(manager))

            with pytest.raises(InvalidNewTransaction):
                manager.propagate_tx(non_signaling_block)

            # at block 59, the feature is MUST_SIGNAL, just before becoming LOCKED_IN:
            [*_, last_block] = add_new_blocks(manager, num_blocks=2, signal_bits=0b1)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*59)
            tx.weight = 30
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            # we don't need to calculate any new state, as block 56's state is saved:
            assert len(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 0
            assert get_ancestor_iteratively_mock.call_count == 0
            calculate_new_state_mock.reset_mock()

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.MUST_SIGNAL}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
            assert artifacts.bit_signaling_service.get_not_support_features() == []

            # at block 60, the feature becomes LOCKED_IN:
            [*_, last_block] = add_new_blocks(manager, 1)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*60)
            tx.weight = 30
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 60
            assert get_ancestor_iteratively_mock.call_count == 0

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.LOCKED_IN}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
            assert artifacts.bit_signaling_service.get_not_support_features() == []

            # we add one block before resetting the mock, just to make sure block 60 gets a chance to be saved
            add_new_blocks(manager, 1)
            calculate_new_state_mock.reset_mock()

            # at block 71, the feature is LOCKED_IN, just before becoming ACTIVE:
            [*_, last_block] = add_new_blocks(manager, 10)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*71)
            tx.weight = 30
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 64
            assert get_ancestor_iteratively_mock.call_count == 0
            calculate_new_state_mock.reset_mock()

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.LOCKED_IN}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

            assert artifacts.bit_signaling_service.get_support_features() == [Feature.NOP_FEATURE_1]
            assert artifacts.bit_signaling_service.get_not_support_features() == []

            # at block 72, the feature becomes ACTIVE, forever:
            [*_, last_block] = add_new_blocks(manager, 1)
            self.simulator.run(60)
            tx = gen_new_tx(manager, address, 6400*72)
            tx.weight = 30
            tx.update_hash()
            assert manager.propagate_tx(tx)
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
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 72
            assert get_ancestor_iteratively_mock.call_count == 0
            calculate_new_state_mock.reset_mock()

            expected_states = {Feature.NOP_FEATURE_1: FeatureState.ACTIVE}
            assert feature_service.get_feature_states(vertex=last_block) == expected_states
            assert feature_service.get_feature_states(vertex=tx) == expected_states
            assert tx.static_metadata.closest_ancestor_block == last_block.hash

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
        feature_service = artifacts.feature_service
        manager = artifacts.manager

        feature_resource = FeatureResource(
            settings=settings,
            feature_service=feature_service,
            tx_storage=artifacts.tx_storage
        )
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


class RocksDBStorageFeatureSimulationTest(BaseFeatureSimulationTest):
    __test__ = True

    def get_rocksdb_directory(self) -> str:
        import tempfile
        tmp_dir = tempfile.mkdtemp()
        self.tmpdirs.append(tmp_dir)
        return tmp_dir

    def get_simulator_builder_from_dir(self, rocksdb_directory: str) -> Builder:
        return self.simulator.get_default_builder() \
            .set_rocksdb_path(path=rocksdb_directory)

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
        feature_service1 = artifacts1.feature_service
        manager1 = artifacts1.manager

        feature_resource = FeatureResource(
            settings=settings,
            feature_service=feature_service1,
            tx_storage=artifacts1.tx_storage
        )
        web_client = StubSite(feature_resource)

        calculate_new_state_mock = Mock(wraps=feature_service1._calculate_new_state)
        get_ancestor_iteratively_mock = Mock(wraps=feature_service1._get_ancestor_iteratively)

        with (
            patch.object(FeatureService, '_calculate_new_state', calculate_new_state_mock),
            patch.object(FeatureService, '_get_ancestor_iteratively', get_ancestor_iteratively_mock),
        ):
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
            # feature states have to be calculated for all blocks in evaluation interval boundaries,
            # down to the first one (after genesis), as this is the first run:
            assert min(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 4
            # no blocks are voided, so we only use the height index:
            assert get_ancestor_iteratively_mock.call_count == 0
            assert artifacts1.tx_storage.get_vertices_count() == 67
            calculate_new_state_mock.reset_mock()

        manager1.stop()
        not_none(artifacts1.rocksdb_storage).close()

        # new builder is created with the same storage from the previous manager
        builder2 = self.get_simulator_builder_from_dir(rocksdb_dir).set_settings(settings)
        artifacts2 = self.simulator.create_artifacts(builder2)
        feature_service = artifacts2.feature_service

        feature_resource = FeatureResource(
            settings=settings,
            feature_service=feature_service,
            tx_storage=artifacts2.tx_storage
        )
        web_client = StubSite(feature_resource)

        calculate_new_state_mock = Mock(wraps=feature_service._calculate_new_state)
        get_ancestor_iteratively_mock = Mock(wraps=feature_service._get_ancestor_iteratively)

        with (
            patch.object(FeatureService, '_calculate_new_state', calculate_new_state_mock),
            patch.object(FeatureService, '_get_ancestor_iteratively', get_ancestor_iteratively_mock),
        ):
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
            # features states are not calculate for any block, as they're all saved:
            assert len(self._calculate_new_state_mock_block_height_calls(calculate_new_state_mock)) == 0
            assert get_ancestor_iteratively_mock.call_count == 0
            assert artifacts2.tx_storage.get_vertices_count() == 67
            calculate_new_state_mock.reset_mock()
