# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from enum import StrEnum, auto, unique


@unique
class NCExecutionState(StrEnum):
    PENDING = auto()  # aka, not even tried to execute it
    SUCCESS = auto()  # execution was successful
    FAILURE = auto()  # execution failed and the transaction is voided
    SKIPPED = auto()  # execution was skipped, usually because the transaction was voided
