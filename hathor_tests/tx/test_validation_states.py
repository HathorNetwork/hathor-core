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

from hathor.transaction.validation_state import ValidationState


def test_validation_states_list_unchanged():
    # XXX: if these change there are some code that make certain assumptions that should be reviewd, in particular:
    # - hathor.transaction.storage.transaction_storage.tx_allow_scope.TxAllowScope.is_allowed
    assert list(ValidationState), [
        ValidationState.INITIAL,
        ValidationState.BASIC,
        ValidationState.CHECKPOINT,
        ValidationState.FULL,
        ValidationState.CHECKPOINT_FULL,
        ValidationState.INVALID,
    ]


def test_validation_states_properties():
    # ValidationState.INITIAL
    assert ValidationState.INITIAL.is_initial() is True
    assert ValidationState.INITIAL.is_at_least_basic() is False
    assert ValidationState.INITIAL.is_valid() is False
    assert ValidationState.INITIAL.is_checkpoint() is False
    assert ValidationState.INITIAL.is_fully_connected() is False
    assert ValidationState.INITIAL.is_partial() is True
    assert ValidationState.INITIAL.is_invalid() is False
    assert ValidationState.INITIAL.is_final() is False
    # ValidationState.BASIC
    assert ValidationState.BASIC.is_initial() is False
    assert ValidationState.BASIC.is_at_least_basic() is True
    assert ValidationState.BASIC.is_valid() is False
    assert ValidationState.BASIC.is_checkpoint() is False
    assert ValidationState.BASIC.is_fully_connected() is False
    assert ValidationState.BASIC.is_partial() is True
    assert ValidationState.BASIC.is_invalid() is False
    assert ValidationState.BASIC.is_final() is False
    # ValidationState.CHECKPOINT
    assert ValidationState.CHECKPOINT.is_initial() is False
    assert ValidationState.CHECKPOINT.is_at_least_basic() is True
    assert ValidationState.CHECKPOINT.is_valid() is True
    assert ValidationState.CHECKPOINT.is_checkpoint() is True
    assert ValidationState.CHECKPOINT.is_fully_connected() is False
    assert ValidationState.CHECKPOINT.is_partial() is True
    assert ValidationState.CHECKPOINT.is_invalid() is False
    assert ValidationState.CHECKPOINT.is_final() is False
    # ValidationState.FULL
    assert ValidationState.FULL.is_initial() is False
    assert ValidationState.FULL.is_at_least_basic() is True
    assert ValidationState.FULL.is_valid() is True
    assert ValidationState.FULL.is_checkpoint() is False
    assert ValidationState.FULL.is_fully_connected() is True
    assert ValidationState.FULL.is_partial() is False
    assert ValidationState.FULL.is_invalid() is False
    assert ValidationState.FULL.is_final() is True
    # ValidationState.CHECKPOINT_FULL
    assert ValidationState.CHECKPOINT_FULL.is_initial() is False
    assert ValidationState.CHECKPOINT_FULL.is_at_least_basic() is True
    assert ValidationState.CHECKPOINT_FULL.is_valid() is True
    assert ValidationState.CHECKPOINT_FULL.is_checkpoint() is True
    assert ValidationState.CHECKPOINT_FULL.is_fully_connected() is True
    assert ValidationState.CHECKPOINT_FULL.is_partial() is False
    assert ValidationState.CHECKPOINT_FULL.is_invalid() is False
    assert ValidationState.CHECKPOINT_FULL.is_final() is True
    # ValidationState.INVALID
    assert ValidationState.INVALID.is_initial() is False
    assert ValidationState.INVALID.is_at_least_basic() is False
    assert ValidationState.INVALID.is_valid() is False
    assert ValidationState.INVALID.is_checkpoint() is False
    assert ValidationState.INVALID.is_fully_connected() is False
    assert ValidationState.INVALID.is_partial() is False
    assert ValidationState.INVALID.is_invalid() is True
    assert ValidationState.INVALID.is_final() is True


def test_validation_states_partition_properties():
    # these set of properties must not overlap and must cover all states:
    # - is_partial
    # - is_fully_connected
    # - is_invalid
    # this means that:
    # - for each state at most one of these properties must be true
    # - for each state at least one of these properties must be true
    properties = [
        ValidationState.is_partial,
        ValidationState.is_fully_connected,
        ValidationState.is_invalid,
    ]
    for state in ValidationState:
        assert sum(int(prop(state)) for prop in properties) == 1
