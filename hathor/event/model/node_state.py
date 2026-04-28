# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from enum import Enum


class NodeState(Enum):
    LOAD = 0
    SYNC = 1
