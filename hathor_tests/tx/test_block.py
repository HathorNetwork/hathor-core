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

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import BlockIsMissingSignal, BlockIsSignaling, FeatureService
from hathor.transaction import Block
from hathor.transaction.exceptions import BlockMustSignalError
from hathor.transaction.static_metadata import BlockStaticMetadata
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.validation_state import ValidationState
from hathor.util import not_none
from hathor.verification.block_verifier import BlockVerifier
from hathor_tests.unittest import TestBuilder


def test_calculate_feature_activation_bit_counts_genesis():
    settings = get_global_settings()
    storage = TestBuilder().build().tx_storage
    genesis_block = storage.get_block(settings.GENESIS_BLOCK_HASH)
    result = genesis_block.static_metadata.feature_activation_bit_counts

    assert result == [0, 0, 0, 0]


@pytest.fixture
def tx_storage() -> TransactionStorage:
    artifacts = TestBuilder().build()
    storage = artifacts.tx_storage
    indexes = artifacts.indexes
    feature_activation_bits = [
        0b0000,  # 0: boundary block
        0b1010,
        0b1110,
        0b1110,

        0b0011,  # 4: boundary block
        0b0111,
        0b1111,
        0b0101,

        0b0000,  # 8: boundary block
        0b0000,
    ]

    for height, bits in enumerate(feature_activation_bits):
        if height == 0:
            continue
        parent = not_none(storage.get_block_by_height(height - 1))
        block = Block(signal_bits=bits, parents=[parent.hash], storage=storage)
        block.update_hash()
        block.get_metadata().validation = ValidationState.FULL
        block.init_static_metadata_from_storage(get_global_settings(), storage)
        storage.save_transaction(block)
        indexes.height.add_new(height, block.hash, block.timestamp)

    return storage


@pytest.mark.parametrize(
    ['block_height', 'expected_counts'],
    [
        (0, [0, 0, 0, 0]),
        (1, [0, 1, 0, 1]),
        (2, [0, 2, 1, 2]),
        (3, [0, 3, 2, 3]),
        (4, [1, 1, 0, 0]),
        (5, [2, 2, 1, 0]),
        (6, [3, 3, 2, 1]),
        (7, [4, 3, 3, 1]),
        (8, [0, 0, 0, 0]),
        (9, [0, 0, 0, 0]),
    ]
)
def test_calculate_feature_activation_bit_counts(
    tx_storage: TransactionStorage,
    block_height: int,
    expected_counts: list[int]
) -> None:
    block = not_none(tx_storage.get_block_by_height(block_height))
    assert block.static_metadata.feature_activation_bit_counts == expected_counts


def test_get_height() -> None:
    static_metadata = BlockStaticMetadata(
        min_height=0,
        height=10,
        feature_activation_bit_counts=[],
        feature_states={},
    )
    block = Block()
    block.set_static_metadata(static_metadata)

    assert block.get_height() == 10


@pytest.mark.parametrize(
    ['signal_bits', 'expected_bit_list'],
    [
        (0x00, [0, 0, 0, 0]),  # 0
        (0x01, [1, 0, 0, 0]),  # 1
        (0xF1, [1, 0, 0, 0]),  # 1
        (0x07, [1, 1, 1, 0]),  # 7
        (0xF7, [1, 1, 1, 0]),  # 7
        (0x0F, [1, 1, 1, 1]),  # 0xF
        (0xFF, [1, 1, 1, 1]),  # 0xF
    ]
)
def test_get_feature_activation_bit_list(signal_bits: int, expected_bit_list: list[int]) -> None:
    block = Block(signal_bits=signal_bits)
    result = block._get_feature_activation_bit_list()

    assert result == expected_bit_list


def test_get_feature_activation_bit_value() -> None:
    block = Block(signal_bits=0b0000_0100)

    assert block.get_feature_activation_bit_value(0) == 0
    assert block.get_feature_activation_bit_value(1) == 0
    assert block.get_feature_activation_bit_value(2) == 1
    assert block.get_feature_activation_bit_value(3) == 0


def test_verify_must_signal() -> None:
    settings = Mock(spec_set=HathorSettings)
    settings.CHECKPOINTS = []
    feature_service = Mock(spec_set=FeatureService)
    feature_service.is_signaling_mandatory_features = Mock(
        return_value=BlockIsMissingSignal(feature=Feature.NOP_FEATURE_1)
    )
    verifier = BlockVerifier(settings=settings, feature_service=feature_service, daa=Mock(), tx_storage=Mock())
    block = Block()

    with pytest.raises(BlockMustSignalError) as e:
        verifier.verify_mandatory_signaling(block)

    assert str(e.value) == "Block must signal support for feature 'NOP_FEATURE_1' during MUST_SIGNAL phase."


def test_verify_must_not_signal() -> None:
    settings = Mock(spec_set=HathorSettings)
    settings.CHECKPOINTS = []
    feature_service = Mock(spec_set=FeatureService)
    feature_service.is_signaling_mandatory_features = Mock(return_value=BlockIsSignaling())
    verifier = BlockVerifier(settings=settings, feature_service=feature_service, daa=Mock(), tx_storage=Mock())
    block = Block()

    verifier.verify_mandatory_signaling(block)
