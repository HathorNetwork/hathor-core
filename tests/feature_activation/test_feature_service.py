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

from hathor.feature_activation import feature_service
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings
from hathor.transaction import Block


@pytest.fixture
def block_mocks() -> list[Block]:
    mocks = []
    feature_activation_bits = [
        0b0110,  # 0: boundary block
        0b0010,
        0b0110,
        0b0010,

        0b0011,  # 4: boundary block
        0b0011,
        0b0011,
        0b0001,

        0b0000,  # 8: boundary block
        0b0000,
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
    ]

    for i, bits in enumerate(feature_activation_bits):
        mock = Mock(spec_set=Block)
        mocks.append(mock)

        mock.is_genesis = i == 0
        mock.calculate_height = Mock(return_value=i)
        mock.get_block_parent = Mock(return_value=mocks[i - 1])
        mock.get_feature_activation_bits = Mock(return_value=bits)

    return mocks


@pytest.fixture
def service() -> FeatureService:
    settings = Settings(
        evaluation_interval=4,
        default_threshold=3
    )
    service = FeatureService(settings=settings)

    return service


def test_get_state_genesis(block_mocks: list[Block], service: FeatureService):
    block = block_mocks[0]
    result = service.get_state(block=block, feature=Mock())

    assert result == FeatureState.DEFINED


@pytest.mark.parametrize('block_height', [0, 1, 2, 3])
def test_get_state_first_interval(block_mocks: list[Block], service: FeatureService, block_height: int):
    block = block_mocks[block_height]
    result = service.get_state(block=block, feature=Mock())

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
def test_get_state_from_defined(
    block_mocks: list[Block],
    block_height: int,
    start_height: int,
    expected_state: FeatureState
):
    settings = Settings.construct(
        evaluation_interval=4,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(start_height=start_height)
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == expected_state


@pytest.mark.parametrize('block_height', [8, 9, 10, 11, 12, 13])
@pytest.mark.parametrize('timeout_height', [4, 8])
def test_get_state_from_started_to_failed(block_mocks: list[Block], block_height: int, timeout_height: int):
    settings = Settings.construct(
        evaluation_interval=4,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                start_height=0,
                timeout_height=timeout_height,
                activate_on_timeout=False
            )
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.FAILED


@pytest.mark.parametrize('block_height', [8, 9, 10, 11, 12, 13])
@pytest.mark.parametrize('timeout_height', [4, 8])
@pytest.mark.parametrize('minimum_activation_height', [0, 4, 8])
def test_get_state_from_started_to_active_on_timeout(
    block_mocks: list[Block],
    block_height: int,
    timeout_height: int,
    minimum_activation_height: int
):
    settings = Settings.construct(
        evaluation_interval=4,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                start_height=0,
                timeout_height=timeout_height,
                activate_on_timeout=True,
                minimum_activation_height=minimum_activation_height
            )
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.ACTIVE


@pytest.mark.parametrize('block_height', [8, 9, 10, 11, 12, 13])
@pytest.mark.parametrize('minimum_activation_height', [0, 4, 8])
@pytest.mark.parametrize('default_threshold', [0, 1, 2, 3])
def test_get_state_from_started_to_active_on_default_threshold(
    block_mocks: list[Block],
    block_height: int,
    minimum_activation_height: int,
    default_threshold: int
):
    settings = Settings.construct(
        evaluation_interval=4,
        default_threshold=default_threshold,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=1,
                start_height=0,
                timeout_height=400,
                threshold=None,
                minimum_activation_height=minimum_activation_height
            )
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.ACTIVE


@pytest.mark.parametrize('block_height', [8, 9, 10, 11, 12, 13])
@pytest.mark.parametrize('minimum_activation_height', [0, 4, 8])
@pytest.mark.parametrize('custom_threshold', [0, 1, 2, 3])
def test_get_state_from_started_to_active_on_custom_threshold(
    block_mocks: list[Block],
    block_height: int,
    minimum_activation_height: int,
    custom_threshold: int
):
    settings = Settings.construct(
        evaluation_interval=4,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=1,
                start_height=0,
                timeout_height=400,
                threshold=custom_threshold,
                minimum_activation_height=minimum_activation_height
            )
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.ACTIVE


@pytest.mark.parametrize('block_height', [8, 9, 10, 11])
@pytest.mark.parametrize(
    ['activate_on_timeout', 'timeout_height', 'minimum_activation_height'],
    [
        (False, 12, 0),
        (True, 4, 12),
        (True, 8, 12),
    ]
)
def test_get_state_from_started_to_started(
    block_mocks: list[Block],
    block_height: int,
    timeout_height: int,
    activate_on_timeout: int,
    minimum_activation_height: int
):
    settings = Settings.construct(
        evaluation_interval=4,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                bit=3,
                start_height=0,
                timeout_height=timeout_height,
                activate_on_timeout=activate_on_timeout,
                minimum_activation_height=minimum_activation_height
            )
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.STARTED


@pytest.mark.parametrize('block_height', [12, 13, 14, 15])
def test_get_state_from_active(block_mocks: list[Block], block_height: int):
    settings = Settings.construct(
        evaluation_interval=4,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                start_height=0,
                timeout_height=4,
                activate_on_timeout=True
            )
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.ACTIVE


@pytest.mark.parametrize('block_height', [12, 13, 14, 15])
def test_get_state_from_failed(block_mocks: list[Block], block_height: int):
    settings = Settings.construct(
        evaluation_interval=4,
        features={
            Feature.NOP_FEATURE_1: Criteria.construct(
                start_height=0,
                timeout_height=4
            )
        }
    )
    service = FeatureService(settings=settings)
    block = block_mocks[block_height]

    result = service.get_state(block=block, feature=Feature.NOP_FEATURE_1)

    assert result == FeatureState.FAILED


def test_get_bits_description():
    criteria_mock_1 = Criteria.construct()
    criteria_mock_2 = Criteria.construct()
    settings = Settings.construct(
        features={
            Feature.NOP_FEATURE_1: criteria_mock_1,
            Feature.NOP_FEATURE_2: criteria_mock_2
        }
    )
    service = FeatureService(settings=settings)

    def get_state(self, *, block: Block, feature: Feature):
        states = {
            Feature.NOP_FEATURE_1: FeatureState.STARTED,
            Feature.NOP_FEATURE_2: FeatureState.FAILED
        }
        return states[feature]

    with patch('hathor.feature_activation.feature_service.FeatureService.get_state', get_state):
        result = service.get_bits_description(block=Mock())

    expected = {
        Feature.NOP_FEATURE_1: (criteria_mock_1, FeatureState.STARTED),
        Feature.NOP_FEATURE_2: (criteria_mock_2, FeatureState.FAILED),
    }

    assert result == expected


def test_get_bit_count_genesis(block_mocks: list[Block], service: FeatureService):
    block = block_mocks[0]

    with pytest.raises(AssertionError) as e:
        service.get_bit_count(boundary_block=block, bit=Mock())

    assert str(e.value) == 'cannot calculate bit count for genesis'


@pytest.mark.parametrize('block_height', [1, 2, 3, 5, 18, 21])
def test_get_bit_count_invalid(block_mocks: list[Block], service: FeatureService, block_height: int):
    block = block_mocks[block_height]

    with pytest.raises(AssertionError) as e:
        service.get_bit_count(boundary_block=block, bit=Mock())

    assert str(e.value) == 'cannot calculate bit count for a non-boundary block'


@pytest.mark.parametrize(
    ['block_height', 'bit', 'expected_count'],
    [
        (4, 0, 0),
        (4, 1, 4),
        (4, 2, 2),

        (8, 0, 4),
        (8, 1, 3),
        (8, 2, 0),
    ]
)
def test_get_bit_count(
    block_mocks: list[Block],
    service: FeatureService,
    block_height: int,
    bit: int,
    expected_count: int
):
    block = block_mocks[block_height]
    result = service.get_bit_count(boundary_block=block, bit=bit)

    assert result == expected_count


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
def test_get_ancestor_at_height_invalid(block_mocks: list[Block], block_height: int, ancestor_height: int):
    block = block_mocks[block_height]
    _block = feature_service._Block.from_block(block)

    with pytest.raises(AssertionError) as e:
        feature_service._get_ancestor_at_height(_block=_block, height=ancestor_height)

    assert str(e.value) == (
        f"ancestor height must be lower than the block's height: {ancestor_height} >= {block_height}"
    )


@pytest.mark.parametrize(
    ['block_height', 'ancestor_height'],
    [
        (21, 20),
        (21, 10),
        (21, 0),
        (15, 10),
        (15, 0),
        (1, 0),
    ]
)
def test_get_ancestor_at_height(block_mocks: list[Block], block_height: int, ancestor_height: int):
    block = block_mocks[block_height]
    _block = feature_service._Block.from_block(block)
    result = feature_service._get_ancestor_at_height(_block=_block, height=ancestor_height)

    assert result.calculate_height() == ancestor_height
