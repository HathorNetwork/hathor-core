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

from unittest.mock import Mock

import pytest

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_description import FeatureDescription
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.resources.feature import FeatureResource
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage
from tests.resources.base_resource import StubSite


@pytest.fixture
def web():
    block_mock = Mock(wraps=Block(), spec_set=Block)
    block_mock.get_feature_activation_bit_counts = Mock(return_value=[0, 1, 0, 0])
    block_mock.hash_hex = 'some_hash'
    block_mock.get_height = Mock(return_value=123)

    tx_storage = Mock(spec_set=TransactionStorage)
    tx_storage.get_best_block = Mock(return_value=block_mock)
    tx_storage.get_transaction = Mock(return_value=block_mock)

    def get_state(*, block: Block, feature: Feature) -> FeatureState:
        return FeatureState.ACTIVE if feature is Feature.NOP_FEATURE_1 else FeatureState.STARTED

    nop_feature_1_criteria = Criteria(
        bit=0,
        start_height=0,
        timeout_height=100,
        version='0.1.0'
    )
    nop_feature_2_criteria = Criteria(
        bit=1,
        start_height=200,
        threshold=2,
        timeout_height=300,
        version='0.2.0'
    )

    feature_service = Mock(spec_set=FeatureService)
    feature_service.get_state = Mock(side_effect=get_state)
    feature_service.get_bits_description = Mock(return_value={
        Feature.NOP_FEATURE_1: FeatureDescription(state=FeatureState.DEFINED, criteria=nop_feature_1_criteria),
        Feature.NOP_FEATURE_2: FeatureDescription(state=FeatureState.LOCKED_IN, criteria=nop_feature_2_criteria),
    })

    feature_settings = FeatureSettings(
        evaluation_interval=4,
        default_threshold=3,
        features={
            Feature.NOP_FEATURE_1: nop_feature_1_criteria,
            Feature.NOP_FEATURE_2: nop_feature_2_criteria
        }
    )

    feature_resource = FeatureResource(
        feature_settings=feature_settings,
        feature_service=feature_service,
        tx_storage=tx_storage
    )

    return StubSite(feature_resource)


def test_get_features(web):
    response = web.get('feature')
    result = response.result.json_value()
    expected = dict(
        block_hash='some_hash',
        block_height=123,
        features=[
            dict(
                name='NOP_FEATURE_1',
                state='ACTIVE',
                acceptance=None,
                threshold=0.75,
                start_height=0,
                minimum_activation_height=0,
                timeout_height=100,
                lock_in_on_timeout=False,
                version='0.1.0'
            ),
            dict(
                name='NOP_FEATURE_2',
                state='STARTED',
                acceptance=0.25,
                threshold=0.5,
                start_height=200,
                minimum_activation_height=0,
                timeout_height=300,
                lock_in_on_timeout=False,
                version='0.2.0'
            )
        ]
    )

    assert result == expected


def test_get_block_features(web):
    response = web.get('feature', args={b'block': b'1234'})
    result = response.result.json_value()
    expected = dict(
        signal_bits=[
            dict(bit=1, signal=0, feature="NOP_FEATURE_2", feature_state="LOCKED_IN")
        ]
    )

    assert result == expected
