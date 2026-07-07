# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import NamedTuple


class Checkpoint(NamedTuple):
    height: int
    hash: bytes
