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

import os
from unittest.mock import Mock, patch

from hathor.event import EventManager
from hathor.execution_manager import ExecutionManager
from hathor.transaction.storage import TransactionStorage


def test_crash_and_exit() -> None:
    tx_storage_mock = Mock(spec_set=TransactionStorage)
    event_manager_mock = Mock(spec_set=EventManager)
    log_mock = Mock()
    manager = ExecutionManager(tx_storage=tx_storage_mock, event_manager=event_manager_mock)
    manager._log = log_mock
    reason = 'some critical failure'

    with patch.object(os, '_exit') as exit_mock:
        manager.crash_and_exit(reason=reason)

    tx_storage_mock.full_node_crashed.assert_called_once()
    event_manager_mock.full_node_crashed.assert_called_once()
    log_mock.critical.assert_called_once_with(
        'Critical failure occurred, causing the full node to halt execution. Manual intervention is required.',
        reason=reason,
        exc_info=True
    )

    exit_mock.assert_called_once_with(-1)
