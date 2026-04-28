# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""
Difficulty Adjustment Algorithm (DAA), block rewards, and transaction weight calculation.

Architecture:
    hathor.daa.common    — utility functions, types, and the ``DAAConfig`` value object
    hathor.daa.daa       — ``DifficultyAdjustmentAlgorithm``, parameterized by a ``DAAConfig``
    hathor.daa.factory   — ``DAAFactory`` builds the right DAA for a block's feature state
"""

from hathor.daa.common import DAAConfig, DAAVersion, TestMode
from hathor.daa.daa import DifficultyAdjustmentAlgorithm
from hathor.daa.factory import DAAFactory

__all__ = [
    'DAAConfig',
    'DAAFactory',
    'DAAVersion',
    'DifficultyAdjustmentAlgorithm',
    'TestMode',
]
