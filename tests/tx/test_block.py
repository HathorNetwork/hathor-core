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
    ['version', 'expected_bits'],
    [
        (0x0001, 0),
        (0x0101, 1),
        (0xF101, 1),
        (0x0601, 6),
        (0xF601, 6),
        (0x0F01, 0xF),
        (0xFF01, 0xF),
    ]
)
def test_get_feature_activation_bits(version, expected_bits):
    block = Block(version=version)

    assert block.get_feature_activation_bits() == expected_bits
