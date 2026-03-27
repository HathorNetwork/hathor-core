# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Difficulty Adjustment Algorithm (DAA), block rewards, and transaction weight calculation.

Architecture (composition with shared utilities):
    hathor.daa.common   — shared types and pure algorithm implementations
    hathor.daa.v1       — DifficultyAdjustmentAlgorithmV1 (original 30s target, normal rewards)
    hathor.daa.v2       — DifficultyAdjustmentAlgorithmV2 (reduced 7.5s target, reduced rewards)
    hathor.daa.daa      — DifficultyAdjustmentAlgorithm (feature-aware facade, holds V1 + V2)
"""

from hathor.daa.common import DAAVersion, TestMode
from hathor.daa.daa import DifficultyAdjustmentAlgorithm
from hathor.daa.v1 import DifficultyAdjustmentAlgorithmV1
from hathor.daa.v2 import DifficultyAdjustmentAlgorithmV2

__all__ = [
    'DAAVersion',
    'DifficultyAdjustmentAlgorithm',
    'DifficultyAdjustmentAlgorithmV1',
    'DifficultyAdjustmentAlgorithmV2',
    'TestMode',
]
