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

from unittest.mock import Mock, call

import pytest

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.sync_v2.request_response_command import MultipleRequestResponseCommand, SingleRequestResponseCommand


def test_single_success() -> None:
    request_message = ProtocolMessages.GET_BEST_BLOCK
    message_sender = Mock()
    payload = 'some_payload'
    response = 'some_response'
    cmd = SingleRequestResponseCommand[str](
        message_sender=message_sender,
        request_message=request_message
    )

    deferred = cmd.request_data(payload)
    received = cmd.receive_response(response)

    message_sender.assert_called_once_with(request_message, payload)
    assert deferred.result == response
    assert received is True


def test_single_repeated_request() -> None:
    request_message = ProtocolMessages.GET_BEST_BLOCK
    message_sender = Mock()
    payload = 'some_payload'
    response = 'some_response'
    cmd = SingleRequestResponseCommand[str](
        message_sender=message_sender,
        request_message=request_message
    )

    deferred = cmd.request_data(payload)

    with pytest.raises(AssertionError) as e:
        cmd.request_data(payload)

    assert str(e.value) == 'cannot request data, fetch already in progress'

    received = cmd.receive_response(response)

    message_sender.assert_called_once_with(request_message, payload)
    assert deferred.result == response
    assert received is True


def test_single_no_request() -> None:
    request_message = ProtocolMessages.GET_BEST_BLOCK
    message_sender = Mock()
    response = 'some_response'
    cmd = SingleRequestResponseCommand[str](
        message_sender=message_sender,
        request_message=request_message
    )

    received = cmd.receive_response(response)

    message_sender.assert_not_called()
    assert received is False


def test_multiple_success() -> None:
    request_message = ProtocolMessages.GET_BEST_BLOCK
    message_sender = Mock()
    cmd = MultipleRequestResponseCommand[str, str](
        message_sender=message_sender,
        request_message=request_message
    )

    deferred1 = cmd.request_data('key1', 'payload1')
    deferred2 = cmd.request_data('key2', 'payload2')
    received1 = cmd.receive_response('key1', 'response1')
    received2 = cmd.receive_response('key2', 'response2')

    assert message_sender.call_count == 2
    message_sender.assert_has_calls([call(request_message, 'payload1'), call(request_message, 'payload2')])
    assert deferred1.result == 'response1'
    assert deferred2.result == 'response2'
    assert received1 is True
    assert received2 is True


def test_multiple_repeated_request() -> None:
    request_message = ProtocolMessages.GET_BEST_BLOCK
    message_sender = Mock()
    cmd = MultipleRequestResponseCommand[str, str](
        message_sender=message_sender,
        request_message=request_message
    )

    deferred1 = cmd.request_data('key1', 'payload1')

    with pytest.raises(AssertionError) as e:
        cmd.request_data('key1', 'payload1')

    assert str(e.value) == 'cannot request data, fetch already in progress'

    deferred2 = cmd.request_data('key2', 'payload2')
    received1 = cmd.receive_response('key1', 'response1')
    received2 = cmd.receive_response('key2', 'response2')

    assert message_sender.call_count == 2
    message_sender.assert_has_calls([call(request_message, 'payload1'), call(request_message, 'payload2')])
    assert deferred1.result == 'response1'
    assert deferred2.result == 'response2'
    assert received1 is True
    assert received2 is True


def test_multiple_no_request() -> None:
    request_message = ProtocolMessages.GET_BEST_BLOCK
    message_sender = Mock()
    cmd = MultipleRequestResponseCommand[str, str](
        message_sender=message_sender,
        request_message=request_message
    )

    deferred2 = cmd.request_data('key2', 'payload2')
    received1 = cmd.receive_response('key1', 'response1')
    received2 = cmd.receive_response('key2', 'response2')

    message_sender.assert_called_once_with(request_message, 'payload2')
    assert deferred2.result == 'response2'
    assert received1 is False
    assert received2 is True
