# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
