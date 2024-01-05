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

from hathor.conf.get_settings import get_settings
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import BlockIsMissingSignal, BlockIsSignaling, FeatureService
from hathor.transaction import Block, TransactionMetadata
from hathor.transaction.exceptions import BlockMustSignalError
from hathor.transaction.storage import TransactionMemoryStorage, TransactionStorage
from hathor.verification.block_verifier import BlockVerifier


def test_calculate_feature_activation_bit_counts_genesis():
    settings = get_settings()
    storage = TransactionMemoryStorage()
    genesis_block = storage.get_transaction(settings.GENESIS_BLOCK_HASH)
    assert isinstance(genesis_block, Block)
    result = genesis_block.get_feature_activation_bit_counts()

    assert result == [0, 0, 0, 0]


@pytest.fixture
def block_mocks() -> list[Block]:
    settings = get_settings()
    blocks: list[Block] = []
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

    for i, bits in enumerate(feature_activation_bits):
        genesis_hash = settings.GENESIS_BLOCK_HASH
        block_hash = genesis_hash if i == 0 else b'some_hash'

        storage = Mock(spec_set=TransactionStorage)
        storage.get_metadata = Mock(return_value=None)

        block = Block(hash=block_hash, storage=storage, signal_bits=bits)
        blocks.append(block)

        get_block_parent_mock = Mock(return_value=blocks[i - 1])
        setattr(block, 'get_block_parent', get_block_parent_mock)

    return blocks


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
    block_mocks: list[Block],
    block_height: int,
    expected_counts: list[int]
) -> None:
    block = block_mocks[block_height]
    result = block.get_feature_activation_bit_counts()

    assert result == expected_counts


def test_get_height():
    block_hash = b'some_hash'
    block_height = 10
    metadata = TransactionMetadata(hash=block_hash, height=block_height)

    storage = Mock(spec_set=TransactionStorage)
    storage.get_metadata = Mock(side_effect=lambda _hash: metadata if _hash == block_hash else None)

    block = Block(hash=block_hash, storage=storage)

    assert block.get_height() == block_height


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
    feature_service = Mock(spec_set=FeatureService)
    feature_service.is_signaling_mandatory_features = Mock(
        return_value=BlockIsMissingSignal(feature=Feature.NOP_FEATURE_1)
    )
    verifier = BlockVerifier(settings=settings, feature_service=feature_service, daa=Mock())
    block = Block()

    with pytest.raises(BlockMustSignalError) as e:
        verifier.verify_mandatory_signaling(block)

    assert str(e.value) == "Block must signal support for feature 'NOP_FEATURE_1' during MUST_SIGNAL phase."


def test_verify_must_not_signal() -> None:
    settings = Mock(spec_set=HathorSettings)
    feature_service = Mock(spec_set=FeatureService)
    feature_service.is_signaling_mandatory_features = Mock(return_value=BlockIsSignaling())
    verifier = BlockVerifier(settings=settings, feature_service=feature_service, daa=Mock())
    block = Block()

    verifier.verify_mandatory_signaling(block)
