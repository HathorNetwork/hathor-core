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
from structlog.testing import capture_logs

from hathor.feature_activation.bit_signaling_service import BitSignalingService
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_description import FeatureDescription
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage


@pytest.mark.parametrize(
    'features_description',
    [
        {},
        {
            Feature.NOP_FEATURE_1: FeatureDescription(state=FeatureState.DEFINED, criteria=Mock())
        },
        {
            Feature.NOP_FEATURE_1: FeatureDescription(state=FeatureState.FAILED, criteria=Mock()),
            Feature.NOP_FEATURE_2: FeatureDescription(state=FeatureState.ACTIVE, criteria=Mock())
        }
    ]
)
@pytest.mark.parametrize(
    ['support_features', 'not_support_features'],
    [
        ({Feature.NOP_FEATURE_1}, set()),
        (set(), {Feature.NOP_FEATURE_2}),
        ({Feature.NOP_FEATURE_1}, {Feature.NOP_FEATURE_2}),
        ({Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2}, set()),
    ]
)
def test_generate_signal_bits_no_signaling_features(
    features_description: dict[Feature, FeatureDescription],
    support_features: set[Feature],
    not_support_features: set[Feature]
) -> None:
    signal_bits = _test_generate_signal_bits(features_description, support_features, not_support_features)

    assert signal_bits == 0


@pytest.mark.parametrize(
    ['support_features', 'not_support_features', 'expected_signal_bits'],
    [
        ({Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_3}, set(), 0b1001),
        (set(), {Feature.NOP_FEATURE_2}, 0b0000),
        ({Feature.NOP_FEATURE_1}, {Feature.NOP_FEATURE_2, Feature.NOP_FEATURE_3}, 0b0001),
        ({Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2, Feature.NOP_FEATURE_3}, set(), 0b1011),
    ]
)
def test_generate_signal_bits_signaling_features(
    support_features: set[Feature],
    not_support_features: set[Feature],
    expected_signal_bits: int,
) -> None:
    features_description = {
        Feature.NOP_FEATURE_1: FeatureDescription(
            state=FeatureState.STARTED,
            criteria=Criteria(
                bit=0,
                start_height=0,
                timeout_height=2*40320,
                version='0.0.0'
            )
        ),
        Feature.NOP_FEATURE_2: FeatureDescription(
            state=FeatureState.MUST_SIGNAL,
            criteria=Criteria(
                bit=1,
                start_height=0,
                timeout_height=2*40320,
                version='0.0.0'
            )
        ),
        Feature.NOP_FEATURE_3: FeatureDescription(
            state=FeatureState.LOCKED_IN,
            criteria=Criteria(
                bit=3,
                start_height=0,
                timeout_height=2*40320,
                version='0.0.0'
            )
        )
    }

    signal_bits = _test_generate_signal_bits(features_description, support_features, not_support_features)

    assert signal_bits == expected_signal_bits


@pytest.mark.parametrize(
    ['support_features', 'not_support_features', 'expected_signal_bits'],
    [
        ({Feature.NOP_FEATURE_3, Feature.NOP_FEATURE_2}, set(), 0b1011),
        (set(), {Feature.NOP_FEATURE_1}, 0b0010),
        ({Feature.NOP_FEATURE_2}, {Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_3}, 0b0010),
        ({Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2, Feature.NOP_FEATURE_3}, set(), 0b1011),
        (set(), {Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2, Feature.NOP_FEATURE_3}, 0b0000),
    ]
)
def test_generate_signal_bits_signaling_features_with_defaults(
    support_features: set[Feature],
    not_support_features: set[Feature],
    expected_signal_bits: int,
) -> None:
    features_description = {
        Feature.NOP_FEATURE_1: FeatureDescription(
            state=FeatureState.STARTED,
            criteria=Criteria(
                bit=0,
                start_height=0,
                timeout_height=2*40320,
                version='0.0.0',
                signal_support_by_default=True
            )
        ),
        Feature.NOP_FEATURE_2: FeatureDescription(
            state=FeatureState.MUST_SIGNAL,
            criteria=Criteria(
                bit=1,
                start_height=0,
                timeout_height=2*40320,
                version='0.0.0',
                signal_support_by_default=True
            )
        ),
        Feature.NOP_FEATURE_3: FeatureDescription(
            state=FeatureState.LOCKED_IN,
            criteria=Criteria(
                bit=3,
                start_height=0,
                timeout_height=2*40320,
                version='0.0.0',
            )
        )
    }

    signal_bits = _test_generate_signal_bits(features_description, support_features, not_support_features)

    assert signal_bits == expected_signal_bits


def _test_generate_signal_bits(
    features_description: dict[Feature, FeatureDescription],
    support_features: set[Feature],
    not_support_features: set[Feature]
) -> int:
    feature_service = Mock(spec_set=FeatureService)
    feature_service.get_bits_description = lambda block: features_description

    service = BitSignalingService(
        feature_settings=FeatureSettings(),
        feature_service=feature_service,
        tx_storage=Mock(),
        support_features=support_features,
        not_support_features=not_support_features
    )

    return service.generate_signal_bits(block=Mock())


@pytest.mark.parametrize(
    ['support_features', 'not_support_features', 'invalid_features'],
    [
        (
            {Feature.NOP_FEATURE_2},
            {Feature.NOP_FEATURE_2},
            ['NOP_FEATURE_2'],
        ),
        (
            {Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2},
            {Feature.NOP_FEATURE_2},
            ['NOP_FEATURE_2'],
        ),
        (
            {Feature.NOP_FEATURE_1},
            {Feature.NOP_FEATURE_2, Feature.NOP_FEATURE_1},
            ['NOP_FEATURE_1'],
        ),
        (
            {Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2},
            {Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2},
            ['NOP_FEATURE_1', 'NOP_FEATURE_2'],
        )
    ]
)
def test_support_intersection_validation(
    support_features: set[Feature],
    not_support_features: set[Feature],
    invalid_features: list[str]
) -> None:
    with pytest.raises(ValueError) as e:
        BitSignalingService(
            feature_settings=Mock(),
            feature_service=Mock(),
            tx_storage=Mock(),
            support_features=support_features,
            not_support_features=not_support_features,
        )

    message = str(e.value)
    assert 'Cannot signal both "support" and "not support" for features' in message

    for feature in invalid_features:
        assert feature in message


@pytest.mark.parametrize(
    ['support_features', 'not_support_features', 'non_signaling_features'],
    [
        (
            {Feature.NOP_FEATURE_1},
            set(),
            {'NOP_FEATURE_1'}
        ),
        (
            set(),
            {Feature.NOP_FEATURE_2},
            {'NOP_FEATURE_2'}
        ),
        (
            {Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2},
            set(),
            {'NOP_FEATURE_1', 'NOP_FEATURE_2'}
        ),
    ]
)
def test_non_signaling_features_warning(
    support_features: set[Feature],
    not_support_features: set[Feature],
    non_signaling_features: set[str],
) -> None:
    best_block = Mock(spec_set=Block)
    best_block.get_height = Mock(return_value=123)
    best_block.hash_hex = 'abc'
    tx_storage = Mock(spec_set=TransactionStorage)
    tx_storage.get_best_block = lambda: best_block

    def get_bits_description_mock(block):
        if block == best_block:
            return {}
        raise NotImplementedError

    feature_service = Mock(spec_set=FeatureService)
    feature_service.get_bits_description = get_bits_description_mock

    service = BitSignalingService(
        feature_settings=FeatureSettings(),
        feature_service=feature_service,
        tx_storage=tx_storage,
        support_features=support_features,
        not_support_features=not_support_features,
    )

    with capture_logs() as logs:
        service.start()

    expected_log = dict(
        log_level='warning',
        best_block_height=123,
        best_block_hash='abc',
        non_signaling_features=non_signaling_features,
        event='Considering the current best block, there are signaled features outside their signaling period. '
              'Therefore, signaling for them has no effect. Make sure you are signaling for the desired features.',
    )

    assert expected_log in logs
