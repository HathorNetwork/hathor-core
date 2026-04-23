#  Copyright 2026 Hathor Labs
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

from enum import IntFlag, auto


class VerificationCheck(IntFlag):
    """Each flag represents one invariant enforced by a verify_* method.

    The verification pipeline records flags into a VerificationContext as
    checks run, and at the end of each stage asserts the recorded set covers
    the required set for the vertex's shape. Prevents silent "double skip"
    bugs where two gates disagree and no check fires.
    """
    # Vertex-level (all vertex types)
    VERSION_BASIC = auto()
    OLD_TIMESTAMP = auto()
    POW = auto()
    PARENTS = auto()
    HEADERS = auto()
    OUTPUTS = auto()
    NUMBER_OF_OUTPUTS = auto()
    SIGOPS_OUTPUT = auto()

    # Transaction-level
    PARENTS_BASIC = auto()
    WEIGHT = auto()
    NUMBER_OF_INPUTS = auto()
    SIGOPS_INPUT = auto()
    INPUTS = auto()
    VERSION = auto()
    TOKENS = auto()
    OUTPUT_TOKEN_INDEXES = auto()
    CONFLICT = auto()
    REWARD_LOCKED = auto()

    # Balance: exactly one of BALANCE or BALANCE_POSTPONED must be set after
    # verify(). Nano contracts may produce BALANCE_POSTPONED at verification
    # time; the block executor must upgrade it to BALANCE post-execution.
    BALANCE = auto()
    BALANCE_POSTPONED = auto()

    # Block-level
    NO_INPUTS = auto()
    BLOCK_WEIGHT = auto()
    REWARD = auto()
    CHECKPOINTS = auto()
    HEIGHT = auto()
    MANDATORY_SIGNALING = auto()
    BLOCK_DATA = auto()
    BLOCK_OUTPUT_TOKEN_INDEXES = auto()
    AUX_POW = auto()
    POA = auto()

    # Fee header
    FEE_LIST = auto()

    # Nano header
    NANO_NC_SIGNATURE = auto()
    NANO_ACTIONS = auto()
    NANO_METHOD_CALL = auto()
    NANO_SEQNUM = auto()

    # Token creation
    TOKEN_INFO = auto()
    MINTED_TOKENS = auto()

    # On-chain blueprint
    OCB_PUBKEY_ALLOWED = auto()
    OCB_NC_SIGNATURE = auto()
    OCB_CODE = auto()
