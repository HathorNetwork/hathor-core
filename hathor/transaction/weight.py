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

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(slots=True, frozen=True, order=True)
class Weight:
    """Wrapper dataclass that represents vertex weight."""
    _inner: float

    def __post_init__(self) -> None:
        assert isinstance(self._inner, float)

    def __str__(self) -> str:
        return str(self._inner)

    def __bool__(self) -> bool:
        return bool(self._inner)

    def is_finite(self) -> bool:
        """Return whether this weight is finite."""
        return math.isfinite(self._inner)

    def get(self) -> float:
        """Get the inner float value of this weight."""
        return self._inner

    def add(self, other: Weight | float) -> Weight:
        """Add another weight or float to this weight, creating a new instance with the result."""
        if isinstance(other, Weight):
            return Weight(self._inner + other._inner)

        if isinstance(other, float):
            return Weight(self._inner + other)

        raise ValueError('other value must be either Weight or float')

    def sub(self, other: Weight | float) -> Weight:
        """Subtract another weight or float from this weight, creating a new instance with the result."""
        if isinstance(other, Weight):
            return Weight(self._inner - other._inner)

        if isinstance(other, float):
            return Weight(self._inner - other)

        raise ValueError('other value must be either Weight or float')

    def to_work(self) -> Work:
        """Convert weight to work rounding up to the nearest integer."""
        return Work(math.floor(0.5 + 2 ** self._inner))

    # def logsum(self, other: 'Weight') -> 'Weight':
    #     """ Make a "logarithmic sum" on base 2.
    #
    #     That is `x.logsum(y)` is equivalent to `log2(2**x + 2**y)`, although there are some precision differences.
    #
    #     Currently is just a proxy to `hathor.transaction.sum_weights`.
    #     """
    #     from hathor.transaction import sum_weights
    #     return Weight(sum_weights(self, other))


@dataclass(slots=True, frozen=True, order=True)
class Work:
    """Wrapper dataclass that represents vertex work."""
    _inner: int

    def __post_init__(self) -> None:
        assert isinstance(self._inner, int)

    def __str__(self) -> str:
        return str(self._inner)

    def __bool__(self) -> bool:
        return bool(self._inner)

    def get(self) -> int:
        """Get the inner int value of this work."""
        return self._inner

    def add(self, other: Work | Weight) -> Work:
        """Add another work or weight to this work, creating a new instance with the result."""
        if isinstance(other, Work):
            return Work(self._inner + other._inner)

        if isinstance(other, Weight):
            return self.add(other.to_work())

        raise ValueError('other value must be either Work or Weight')

    def sub(self, other: Work | Weight) -> Work:
        """Subtract another work or weight from this work, creating a new instance with the result."""
        if isinstance(other, Work):
            return Work(self._inner - other._inner)

        if isinstance(other, Weight):
            return self.sub(other.to_work())

        raise ValueError('other value must be either Work or Weight')

    def to_weight(self) -> Weight:
        """Convert work to weight."""
        if self._inner <= 1:
            return Weight(0.0)
        return Weight(math.log2(self._inner))


def calculate_min_significant_weight(score: Work, tol: float) -> Weight:
    """ This function will return the min significant weight to increase score by tol.

    When most peers are updated to store work as integers for their internal score and accumulated weight metadata,
    this function will not be needed anymore. It's only use currently is to make sure miner nodes will produce blocks
    with weight that are high enough for outdated nodes to be able to observe the score increasing.
    """
    return score.to_weight().add(math.log2(2 ** tol - 1))
