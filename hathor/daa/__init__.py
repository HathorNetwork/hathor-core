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

Architecture:
    hathor.daa.common    — utility functions, types, and the ``DAAConfig`` value object
    hathor.daa.daa       — ``DifficultyAdjustmentAlgorithm``, parameterized by a ``DAAConfig``
    hathor.daa.factory   — ``DAAFactory`` builds the right DAA for a block's feature state
"""

from hathor.daa.common import DAAConfig, TestMode
from hathor.daa.daa import DifficultyAdjustmentAlgorithm
from hathor.daa.factory import DAAFactory

__all__ = [
    'DAAConfig',
    'DAAFactory',
    'DifficultyAdjustmentAlgorithm',
    'TestMode',
]
