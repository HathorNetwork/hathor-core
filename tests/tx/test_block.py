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

import pytest

from hathor.transaction import Block


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
