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

from hathor.event.storage import EventMemoryStorage
from hathor.event.websocket.factory import EventWebsocketFactory
from hathor.event.websocket.protocol import EventWebsocketProtocol
from hathor.event.websocket.response import EventResponse, InvalidRequestType
from hathor.simulator.clock import HeapClock
from tests.utils import EventMocker


def test_started_register():
    factory = _get_factory()
    connection = Mock(spec_set=EventWebsocketProtocol)
    connection.send_invalid_request_response = Mock()

    factory.start()
    factory.register(connection)

    connection.send_invalid_request_response.assert_not_called()


def test_non_started_register():
    factory = _get_factory()
    connection = Mock(spec_set=EventWebsocketProtocol)
    connection.send_invalid_request_response = Mock()

    factory.register(connection)

    connection.send_invalid_request_response.assert_called_once_with(InvalidRequestType.EVENT_WS_NOT_RUNNING)


def test_stopped_register():
    factory = _get_factory()
    connection = Mock(spec_set=EventWebsocketProtocol)
    connection.send_invalid_request_response = Mock()

    factory.start()
    factory.stop()
    factory.register(connection)

    connection.send_invalid_request_response.assert_called_once_with(InvalidRequestType.EVENT_WS_NOT_RUNNING)


@pytest.mark.parametrize('can_receive_event', [False, True])
def test_broadcast_event(can_receive_event: bool) -> None:
    n_starting_events = 10
    factory = _get_factory(n_starting_events)
    event = EventMocker.create_event(n_starting_events - 1)
    connection = Mock(spec_set=EventWebsocketProtocol)
    connection.can_receive_event = Mock(return_value=can_receive_event)
    connection.send_event_response = Mock()

    factory.start()
    factory.register(connection)
    factory.broadcast_event(event)

    if not can_receive_event:
        return connection.send_event_response.assert_not_called()

    response = EventResponse(event=event, latest_event_id=n_starting_events - 1)
    connection.send_event_response.assert_called_once_with(response)


def test_broadcast_multiple_events_multiple_connections():
    factory = _get_factory(10)
    connection1 = Mock(spec_set=EventWebsocketProtocol)
    connection1.can_receive_event = Mock(return_value=True)
    connection1.send_event_response = Mock()
    connection2 = Mock(spec_set=EventWebsocketProtocol)
    connection2.can_receive_event = Mock(return_value=True)
    connection2.send_event_response = Mock()

    factory.start()
    factory.register(connection1)
    factory.register(connection2)

    for event_id in range(10):
        event = EventMocker.create_event(event_id)
        factory.broadcast_event(event)

    assert connection1.send_event_response.call_count == 10
    assert connection2.send_event_response.call_count == 10


@pytest.mark.parametrize(
    ['next_expected_event_id', 'can_receive_event'],
    [
        (0, False),
        (0, True),
        (3, True),
        (10, True)
    ]
)
def test_send_next_event_to_connection(next_expected_event_id: int, can_receive_event: bool) -> None:
    n_starting_events = 10
    clock = HeapClock()
    factory = _get_factory(n_starting_events, clock)
    connection = Mock(spec_set=EventWebsocketProtocol)
    connection.send_event_response = Mock()
    connection.can_receive_event = Mock(return_value=can_receive_event)
    connection.next_expected_event_id = Mock(
        side_effect=lambda: next_expected_event_id + connection.send_event_response.call_count
    )

    factory.start()
    factory.register(connection)
    factory.send_next_event_to_connection(connection)

    clock.advance(0)

    if not can_receive_event or next_expected_event_id > n_starting_events - 1:
        return connection.send_event_response.assert_not_called()

    calls = []
    for _id in range(next_expected_event_id, n_starting_events):
        event = EventMocker.create_event(_id)
        response = EventResponse(event=event, latest_event_id=n_starting_events - 1)
        calls.append(call(response))

    assert connection.send_event_response.call_count == n_starting_events - next_expected_event_id
    connection.send_event_response.assert_has_calls(calls)


def _get_factory(n_starting_events: int = 0, clock: HeapClock = HeapClock()) -> EventWebsocketFactory:
    event_storage = EventMemoryStorage()

    for event_id in range(n_starting_events):
        event = EventMocker.create_event(event_id)
        event_storage.save_event(event)

    return EventWebsocketFactory(clock, event_storage)
