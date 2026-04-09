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

import math


def weight_to_work(weight: float) -> int:
    """Convert weight to work rounding up to the nearest integer."""
    return math.floor(0.5 + 2**weight)


def work_to_weight(work: int) -> float:
    """Convert work to weight."""
    if work <= 1:
        return 0.0
    return math.log2(work)


def calculate_min_significant_weight(score: int, tol: float) -> float:
    """ This function will return the min significant weight to increase score by tol.

    When most peers are updated to store work as integers for their internal score and accumulated weight metadata,
    this function will not be needed anymore. It's only use currently is to make sure miner nodes will produce blocks
    with weight that are high enough for outdated nodes to be able to observe the score increasing.
    """
    return work_to_weight(score) + math.log2(2 ** tol - 1)
