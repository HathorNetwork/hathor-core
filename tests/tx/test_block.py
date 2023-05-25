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

from hathor.event.model.event_data import TxMetadata
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage


def test_height():
    block_hash = b'some_hash'
    block_height = 10

    metadata = Mock(spec=TxMetadata)
    metadata.hash = block_hash
    metadata.height = block_height

    storage = Mock(spec_set=TransactionStorage)
    storage.get_metadata = Mock(side_effect=lambda _hash: metadata if _hash == block_hash else None)

    block = Block(hash=block_hash, storage=storage)

    assert block.height == block_height


@pytest.mark.parametrize(
    ['signal_bits', 'expected_bits'],
    [
        (0x00, 0),
        (0x01, 1),
        (0xF1, 1),
        (0x06, 6),
        (0xF6, 6),
        (0x0F, 0xF),
        (0xFF, 0xF),
    ]
)
def test_get_feature_activation_bits(signal_bits: int, expected_bits: int) -> None:
    block = Block(signal_bits=signal_bits)

    assert block.get_feature_activation_bits() == expected_bits
