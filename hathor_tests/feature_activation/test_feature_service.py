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

from unittest.mock import Mock, patch

import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import (
    BlockIsMissingSignal,
    BlockIsSignaling,
    BlockSignalingState,
    FeatureService,
)
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_info import FeatureInfo
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.validation_state import ValidationState
from hathor.util import not_none
from hathor_tests.unittest import TestBuilder


def get_storage(settings: HathorSettings, *, up_to_height: int) -> TransactionStorage:
    artifacts = TestBuilder(settings).build()
    storage = artifacts.tx_storage
    indexes = not_none(artifacts.indexes)
    feature_activation_bits = [
        0b0000,  # 0: boundary block
        0b0010,
        0b0110,
        0b0010,

        0b0011,  # 4: boundary block
        0b0011,
        0b0011,
        0b0001,

        0b0010,  # 8: boundary block
        0b0110,
        0b0000,
        0b0000,

        0b0000,  # 12: boundary block
        0b0000,
        0b0000,
        0b0000,

        0b0000,  # 16: boundary block
        0b0000,
        0b0000,
        0b0000,

        0b0000,  # 20: boundary block
        0b0000,
        0b0000,
        0b0000,

        0b0000,  # 24: boundary block
        0b0000,
    ]

    for height, bits in enumerate(feature_activation_bits[:up_to_height + 1]):
        if height == 0:
            continue
        parent = not_none(storage.get_block_by_height(height - 1))
        block = Block(signal_bits=bits, parents=[parent.hash], storage=storage)
        block.update_hash()
        block.get_metadata().validation = ValidationState.FULL
        block.init_static_metadata_from_storage(settings, storage)
        storage.save_transaction(block)
        indexes.height.add_new(height, block.hash, block.timestamp)

    return storage


def get_settings(*, features: dict[Feature, Criteria]) -> HathorSettings:
    feature_settings = FeatureSettings.construct(
        evaluation_interval=4,
        default_threshold=3,
        features=features,
    )
    settings = get_global_settings()._replace(FEATURE_ACTIVATION=feature_settings)
    return settings


def test_get_state_genesis() -> None:
    settings = get_settings(features={})
    storage = get_storage(settings, up_to_height=0)
    service = FeatureService(settings=settings, tx_storage=storage)
    block = not_none(storage.get_block_by_height(0))
    result = service.get_state(block=block, feature=Mock())

    assert result == FeatureState.DEFINED


@pytest.mark.parametrize('block_height', [0, 1, 2, 3])
def test_get_state_first_interval(block_height: int) -> None:
    settings = get_settings(features={
        Feature.NOP_FEATURE_1: Mock()
    })
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    block = not_none(storage.get_block_by_height(block_height))
    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.DEFINED


@pytest.mark.parametrize('block_height', [4, 5, 6, 7])
@pytest.mark.parametrize(
    ['start_height', 'expected_state'],
    [
        (0, FeatureState.STARTED),
        (4, FeatureState.STARTED),
        (8, FeatureState.DEFINED)
    ]
)
def test_get_state_from_defined(block_height: int, start_height: int, expected_state: FeatureState) -> None:
    features = {
        Feature.NOP_FEATURE_1: Criteria.construct(
            bit=Mock(),
            start_height=start_height,
            timeout_height=Mock(),
            version=Mock()
        )
    }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == expected_state


@pytest.mark.parametrize('block_height', [12, 13, 14, 15, 16, 17])
@pytest.mark.parametrize('timeout_height', [8, 12])
def test_get_state_from_started_to_failed(
    block_height: int,
    timeout_height: int,
) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=timeout_height,
                lock_in_on_timeout=False,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.FAILED


@pytest.mark.parametrize('block_height', [8, 9, 10, 11])
@pytest.mark.parametrize('timeout_height', [8, 12])
def test_get_state_from_started_to_must_signal_on_timeout(
    block_height: int,
    timeout_height: int,
) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=timeout_height,
                lock_in_on_timeout=True,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.MUST_SIGNAL
    service.bit_signaling_service.on_must_signal.assert_called_once_with(Feature.NOP_FEATURE_1)


@pytest.mark.parametrize('block_height', [8, 9, 10, 11])
@pytest.mark.parametrize('default_threshold', [0, 1, 2, 3])
def test_get_state_from_started_to_locked_in_on_default_threshold(
    block_height: int,
    default_threshold: int
) -> None:
    feature_settings = FeatureSettings.construct(
        evaluation_interval=4,
        default_threshold=default_threshold,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=1,
                start_height=0,
                timeout_height=400,
                threshold=None,
                version=Mock()
            )
        }
    )
    settings = get_global_settings()._replace(FEATURE_ACTIVATION=feature_settings)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.LOCKED_IN


@pytest.mark.parametrize('block_height', [8, 9, 10, 11])
@pytest.mark.parametrize('custom_threshold', [0, 1, 2, 3])
def test_get_state_from_started_to_locked_in_on_custom_threshold(
    block_height: int,
    custom_threshold: int
) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=1,
                start_height=0,
                timeout_height=400,
                threshold=custom_threshold,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.LOCKED_IN


@pytest.mark.parametrize('block_height', [8, 9, 10, 11])
@pytest.mark.parametrize(
    ['lock_in_on_timeout', 'timeout_height'],
    [
        (False, 12),
        (True, 16),
        (True, 20),
    ]
)
def test_get_state_from_started_to_started(
    block_height: int,
    lock_in_on_timeout: bool,
    timeout_height: int,
) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=timeout_height,
                lock_in_on_timeout=lock_in_on_timeout,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.STARTED


@pytest.mark.parametrize('block_height', [12, 13, 14, 15])
def test_get_state_from_must_signal_to_locked_in(
    block_height: int,
) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=8,
                lock_in_on_timeout=True,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.LOCKED_IN


@pytest.mark.parametrize('block_height', [16, 17, 18, 19])
@pytest.mark.parametrize('minimum_activation_height', [0, 4, 8, 12, 16])
def test_get_state_from_locked_in_to_active(
    block_height: int,
    minimum_activation_height: int,
) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=8,
                minimum_activation_height=minimum_activation_height,
                lock_in_on_timeout=True,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.ACTIVE


@pytest.mark.parametrize('block_height', [16, 17, 18, 19])
@pytest.mark.parametrize('minimum_activation_height', [17, 20, 100])
def test_get_state_from_locked_in_to_locked_in(
    block_height: int,
    minimum_activation_height: int,
) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=8,
                minimum_activation_height=minimum_activation_height,
                lock_in_on_timeout=True,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.LOCKED_IN


@pytest.mark.parametrize('block_height', [20, 21, 22, 23])
def test_get_state_from_active(block_height: int) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=8,
                lock_in_on_timeout=True,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.ACTIVE


@pytest.mark.parametrize('block_height', [16, 17, 18, 19])
def test_caching_mechanism(block_height: int) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=8,
                lock_in_on_timeout=True,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(
        settings=settings,
        tx_storage=storage
    )
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))
    calculate_new_state_mock = Mock(wraps=service._calculate_new_state)

    with patch.object(FeatureService, '_calculate_new_state', calculate_new_state_mock):
        result1 = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

        assert result1 == FeatureState.ACTIVE
        assert calculate_new_state_mock.call_count == 4

        calculate_new_state_mock.reset_mock()
        result2 = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

        assert result2 == FeatureState.ACTIVE
        assert calculate_new_state_mock.call_count == 0


@pytest.mark.parametrize('block_height', [16, 17, 18, 19])
def test_is_feature_active(block_height: int) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=8,
                lock_in_on_timeout=True,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(
        settings=settings,
        tx_storage=storage
    )
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.is_feature_active(vertex=block, feature=Feature.NOP_FEATURE_1)

    assert result is True


@pytest.mark.parametrize('block_height', [12, 13, 14, 15])
def test_get_state_from_failed(block_height: int) -> None:
    features = {
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=Mock(),
                start_height=0,
                timeout_height=8,
                version=Mock()
            )
        }
    settings = get_settings(features=features)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.FAILED


def test_get_state_undefined_feature() -> None:
    settings = get_settings(features={})
    storage = get_storage(settings, up_to_height=10)
    block = not_none(storage.get_block_by_height(10))
    service = FeatureService(settings=settings, tx_storage=storage)
    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.DEFINED


def test_get_feature_info() -> None:
    criteria_mock_1 = Criteria.construct(bit=Mock(), start_height=Mock(), timeout_height=Mock(), version=Mock())
    criteria_mock_2 = Criteria.construct(bit=Mock(), start_height=Mock(), timeout_height=Mock(), version=Mock())
    settings = get_settings(features={
        Feature.NOP_FEATURE_1: criteria_mock_1,
        Feature.NOP_FEATURE_2: criteria_mock_2
    })
    storage = get_storage(settings, up_to_height=0)
    service = FeatureService(
        settings=settings,
        tx_storage=storage
    )
    service.bit_signaling_service = Mock()

    def get_state(self: FeatureService, *, block: Block, feature: Feature) -> FeatureState:
        states = {
            Feature.NOP_FEATURE_1: FeatureState.STARTED,
            Feature.NOP_FEATURE_2: FeatureState.FAILED
        }
        return states[feature]

    with patch('hathor.feature_activation.feature_service.FeatureService.get_state', get_state):
        result = service.get_feature_infos(vertex=Mock(spec_set=Block))

    expected = {
        Feature.NOP_FEATURE_1: FeatureInfo(criteria_mock_1, FeatureState.STARTED),
        Feature.NOP_FEATURE_2: FeatureInfo(criteria_mock_2, FeatureState.FAILED),
    }

    assert result == expected


@pytest.mark.parametrize(
    ['block_height', 'ancestor_height'],
    [
        (21, 21),
        (21, 100),
        (10, 15),
        (10, 11),
        (0, 0),
    ]
)
def test_get_ancestor_at_height_invalid(block_height: int, ancestor_height: int) -> None:
    settings = get_settings(features={})
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    with pytest.raises(AssertionError) as e:
        service._get_ancestor_at_height(block=block, ancestor_height=ancestor_height)

    assert str(e.value) == (
        f"ancestor height must be lower than the block's height: {ancestor_height} >= {block_height}"
    )


@pytest.mark.parametrize(
    ['block_height', 'ancestor_height'],
    [
        (21, 20),
        (21, 18),
        (21, 17),
        (15, 12),
        (15, 11),
        (1, 0),
    ]
)
def test_get_ancestor_at_height(block_height: int, ancestor_height: int) -> None:
    settings = get_settings(features={})
    storage = get_storage(settings, up_to_height=block_height)
    block = not_none(storage.get_block_by_height(block_height))

    get_block_by_height_wrapped = Mock(wraps=storage.get_block_by_height)
    with patch.object(storage, 'get_block_by_height', get_block_by_height_wrapped):
        service = FeatureService(settings=settings, tx_storage=storage)
        service.bit_signaling_service = Mock()
        result = service._get_ancestor_at_height(
            block=block,
            ancestor_height=ancestor_height
        )

        assert get_block_by_height_wrapped.call_count == (
            0 if block_height - ancestor_height <= 1 else 1
        ), 'this should only be called if the ancestor is deeper than one parent away'
        assert result == storage.get_block_by_height(ancestor_height)
        assert result.get_height() == ancestor_height


@pytest.mark.parametrize(
    ['block_height', 'ancestor_height'],
    [
        (21, 20),
        (21, 18),
        (15, 12),
        (15, 11),
        (1, 0),
    ]
)
def test_get_ancestor_at_height_voided(block_height: int, ancestor_height: int) -> None:
    settings = get_settings(features={})
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    parent_block = not_none(storage.get_block_by_height(block_height - 1))
    parent_block.get_metadata().voided_by = {b'some'}

    get_block_by_height_wrapped = Mock(wraps=storage.get_block_by_height)
    with patch.object(storage, 'get_block_by_height', get_block_by_height_wrapped):
        result = service._get_ancestor_at_height(block=block, ancestor_height=ancestor_height)

        assert get_block_by_height_wrapped.call_count == 0
        assert result == storage.get_block_by_height(ancestor_height)
        assert result.get_height() == ancestor_height


@pytest.mark.parametrize(
    ['bit', 'threshold', 'block_height', 'signaling_state'],
    [
        (0, 4, 0, BlockIsSignaling()),
        (0, 4, 3, BlockIsSignaling()),
        (0, 4, 7, BlockIsSignaling()),
        (0, 4, 8, BlockIsSignaling()),
        (0, 4, 11, BlockIsSignaling()),
        (0, 4, 12, BlockIsSignaling()),

        (1, 4, 0, BlockIsSignaling()),
        (1, 4, 3, BlockIsSignaling()),
        (1, 4, 7, BlockIsSignaling()),
        (1, 4, 8, BlockIsSignaling()),
        (1, 4, 9, BlockIsSignaling()),
        (1, 4, 10, BlockIsMissingSignal(feature=Feature.NOP_FEATURE_1)),
        (1, 4, 11, BlockIsMissingSignal(feature=Feature.NOP_FEATURE_1)),
        (1, 4, 12, BlockIsSignaling()),

        (2, 2, 8, BlockIsSignaling()),
        (2, 2, 9, BlockIsSignaling()),
        (2, 2, 10, BlockIsSignaling()),
        (2, 2, 11, BlockIsMissingSignal(feature=Feature.NOP_FEATURE_1)),
        (2, 2, 12, BlockIsSignaling()),
    ]
)
def test_check_must_signal(
    bit: int,
    threshold: int,
    block_height: int,
    signaling_state: BlockSignalingState
) -> None:
    feature_settings = FeatureSettings(
        evaluation_interval=4,
        default_threshold=threshold,
        features={
            Feature.NOP_FEATURE_1: Criteria(
                bit=bit,
                start_height=0,
                timeout_height=12,
                lock_in_on_timeout=True,
                version='0.0.0'
            )
        }
    )
    settings = get_global_settings()._replace(FEATURE_ACTIVATION=feature_settings)
    storage = get_storage(settings, up_to_height=block_height)
    service = FeatureService(settings=settings, tx_storage=storage)
    service.bit_signaling_service = Mock()
    block = not_none(storage.get_block_by_height(block_height))

    result = service.is_signaling_mandatory_features(block)

    assert result == signaling_state
