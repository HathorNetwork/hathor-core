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

from enum import IntEnum, unique


@unique
class ValidationState(IntEnum):
    """

    Possible transitions:

    - Initial
        -> Basic: parents exist, graph information checks-out
        -> Invalid: all information to reach `Basic` was available, but something doesn't check out
        -> Checkpoint: is a block which hash matches a known checkpoint is a parent of a Checkpoint-valid tx
    - Basic
        -> Full: all parents reached `Full`, and validation+consensus ran successfully
        -> Invalid: all information to reach `Full` was available, but something doesn't check out
    - Checkpoint
        -> Checkpoint-Full: when all the chain of parents and inputs up to the genesis exist in the database
    - Full: final
    - Checkpoint-Full: final
    - Invalid: final

    `BASIC` means only the validations that can run without access to the dependencies (parents+inputs, except for
    blocks the block parent has to exist and be at least BASIC) have been run. For example, if it's `BASIC` the weight
    of a tx has been validated and is correct, but it may be spending a tx that has already been spent, we will not run
    this validation until _all_ the dependencies have reached `FULL` or any of them `INVALID` (which should
    automatically invalidate this tx). In theory it should be possible to have even more granular validation (if one of
    the inputs exists, validate that we can spend it), but the complexity for that is too high.

    """
    INITIAL = 0  # aka, not validated
    BASIC = 1  # only graph info has been validated
    CHECKPOINT = 2  # validation can be safely assumed because it traces up to a known checkpoint
    FULL = 3  # fully validated
    CHECKPOINT_FULL = 4  # besides being checkpoint valid, it is fully connected
    INVALID = -1  # not valid, this does not mean not best chain, orphan chains can be valid

    def is_initial(self) -> bool:
        """Short-hand property"""
        return self == ValidationState.INITIAL

    def is_at_least_basic(self) -> bool:
        """Until a validation is final, it is possible to change its state when more information is available."""
        return self >= ValidationState.BASIC

    def is_valid(self) -> bool:
        """Short-hand property."""
        return self in {ValidationState.FULL, ValidationState.CHECKPOINT, ValidationState.CHECKPOINT_FULL}

    def is_checkpoint(self) -> bool:
        """Short-hand property."""
        return self in {ValidationState.CHECKPOINT, ValidationState.CHECKPOINT_FULL}

    def is_fully_connected(self) -> bool:
        """Short-hand property."""
        return self in {ValidationState.FULL, ValidationState.CHECKPOINT_FULL}

    def is_partial(self) -> bool:
        """Short-hand property."""
        return self in {ValidationState.INITIAL, ValidationState.BASIC, ValidationState.CHECKPOINT}

    def is_invalid(self) -> bool:
        """Short-hand property."""
        return self == ValidationState.INVALID

    def is_final(self) -> bool:
        """Until a validation is final, it is possible to change its state when more information is available."""
        return self in {ValidationState.FULL, ValidationState.CHECKPOINT_FULL, ValidationState.INVALID}

    @classmethod
    def from_name(cls, name: str) -> 'ValidationState':
        value = getattr(cls, name.upper(), None)
        if value is None:
            raise ValueError('invalid name')
        return value
