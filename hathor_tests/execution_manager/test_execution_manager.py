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

import sys
from unittest.mock import Mock, patch

from hathor.execution_manager import ExecutionManager
from hathor.reactor import ReactorProtocol


def test_crash_and_exit() -> None:
    def callback() -> None:
        pass

    callback_wrapped = Mock(wraps=callback)
    log_mock = Mock()
    reactor_mock = Mock(spec_set=ReactorProtocol)
    manager = ExecutionManager(reactor_mock)
    manager._log = log_mock
    reason = 'some critical failure'

    manager.register_on_crash_callback(callback_wrapped)

    with patch.object(sys, 'exit') as exit_mock:
        manager.crash_and_exit(reason=reason)

    callback_wrapped.assert_called_once()
    log_mock.critical.assert_called_once_with(
        'Critical failure occurred, causing the full node to halt execution. Manual intervention is required.',
        reason=reason,
        exc_info=True
    )

    reactor_mock.stop.assert_called_once()
    reactor_mock.crash.assert_called_once()
    exit_mock.assert_called_once_with(-1)
