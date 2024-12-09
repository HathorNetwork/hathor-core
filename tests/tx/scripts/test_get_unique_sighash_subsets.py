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

from hathor.transaction.scripts.sighash import (
    SighashAll,
    SighashBitmask,
    SighashRange,
    SighashType,
    get_unique_sighash_subsets,
)


@pytest.mark.parametrize(
    ['sighashes', 'expected'],
    [
        # empty -> 0 subsets
        ([], set()),
        # SighashAll is removed -> 0 subsets
        ([SighashAll(), SighashAll(), SighashAll()], set()),
        # SighashBitmask -> 1 subset
        (
            [SighashAll(), SighashBitmask(inputs=0b101, outputs=0b010)],
            {(frozenset([0, 2]), frozenset([1]))}
        ),
        # SighashRange -> 1 subset
        (
            [SighashAll(), SighashRange(input_start=3, input_end=5, output_start=0, output_end=4)],
            {(frozenset(range(3, 5)), frozenset(range(0, 4)))}
        ),
        # Different Sighash bitmasks -> 2 subsets
        (
            [
                SighashBitmask(inputs=0b111, outputs=0b1),
                SighashBitmask(inputs=0b1, outputs=0b111),
            ],
            {
                (frozenset([0, 1, 2]), frozenset([0])),
                (frozenset([0]), frozenset([0, 1, 2])),
            }
        ),
        # Equal Sighash bitmasks -> 1 subset
        (
            [
                SighashBitmask(inputs=0b111, outputs=0b1),
                SighashBitmask(inputs=0b111, outputs=0b1),
            ],
            {
                (frozenset([0, 1, 2]), frozenset([0])),
            }
        ),
        # Different Sighash bitmask and range -> 2 subsets
        (
            [
                SighashBitmask(inputs=0b111, outputs=0b1),
                SighashRange(input_start=3, input_end=5, output_start=0, output_end=4)
            ],
            {
                (frozenset([0, 1, 2]), frozenset([0])),
                (frozenset(range(3, 5)), frozenset(range(0, 4))),
            }
        ),
        # Equal Sighash bitmask and range -> 1 subset
        (
            [
                SighashBitmask(inputs=0b111, outputs=0b1),
                SighashRange(input_start=0, input_end=3, output_start=0, output_end=1)
            ],
            {
                (frozenset([0, 1, 2]), frozenset([0])),
            }
        ),
    ]
)
def test_get_unique_sighash_subsets(
    sighashes: list[SighashType],
    expected: set[tuple[frozenset[int], frozenset[int]]]
) -> None:
    assert get_unique_sighash_subsets(sighashes) == expected
