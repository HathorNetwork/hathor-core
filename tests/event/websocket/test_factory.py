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
from typing import Iterator, Optional
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from hathor.event import BaseEvent
from hathor.event.storage import EventStorage
from hathor.event.websocket.factory import EventWebsocketFactory
from hathor.event.websocket.protocol import EventWebsocketProtocol
from hathor.event.websocket.request import StreamRequest


@pytest.mark.parametrize(
    ['event_id', 'starting_window_size', 'last_received_event_id', 'expected_to_send_event'],
    [
        # does not send if window is not available
        (0, 0, None, False),
        (0, 0, 10, False),
        (10, 0, 10, False),
        (11, 0, 10, False),

        # send only if window is available and event_id > last_received_event_id
        (0, 100, None, True),
        (0, 100, 10, False),
        (10, 100, 10, False),
        (11, 100, 10, True),
    ]
)
def test_broadcast_event(
    event_id: int,
    starting_window_size: int,
    last_received_event_id: Optional[int],
    expected_to_send_event: bool
) -> None:
    factory = _get_factory()
    event = _create_event(event_id)
    connection = EventWebsocketProtocol()
    connection.available_window_size = starting_window_size
    connection.last_received_event_id = last_received_event_id
    connection.sendMessage = Mock()

    factory.start()
    factory.register(connection)
    factory.broadcast_event(event)

    assert connection.sendMessage.call_count == (1 if expected_to_send_event else 0)
    assert connection.available_window_size == (
        starting_window_size - 1 if expected_to_send_event else starting_window_size
    )


@pytest.mark.parametrize(
    ['n_starting_events', 'starting_window_size', 'last_received_event_id', 'window_size_increment',
     'expected_events_sent'],
    [
        # fresh peer
        (0, 0, None, 30, 0),
        (20, 0, None, 30, 20),
        (60, 0, None, 30, 30),

        # peer with starting window but no last event
        (0, 10, None, 30, 0),
        (20, 10, None, 30, 20),
        (60, 10, None, 30, 40),

        # peer with no starting window but with last event
        (0, 0, 5, 30, 0),
        (20, 0, 5, 30, 14),
        (60, 0, 5, 30, 30),

        # peer with starting window and last event
        (0, 10, 5, 30, 0),
        (20, 10, 5, 30, 14),
        (60, 10, 5, 30, 40),

        # peer processing events one by one
        (0, 0, None, 1, 0),
        (3, 0, None, 1, 1),
        (3, 0, 0, 1, 1),
        (3, 0, 1, 1, 1),
        (3, 0, 2, 1, 0),

        # peer processing events in batches of 50
        (0, 0, None, 50, 0),
        (150, 0, None, 50, 50),
        (150, 0, 50, 50, 50),
        (150, 0, 100, 50, 49),
        (150, 0, 149, 50, 0),
    ]
)
def test_handle_valid_request(
    n_starting_events: int,
    starting_window_size: int,
    last_received_event_id: Optional[int],
    window_size_increment: int,
    expected_events_sent: int
) -> None:
    factory = _get_factory(n_starting_events)
    connection = EventWebsocketProtocol()
    connection.available_window_size = starting_window_size
    connection.sendMessage = Mock()
    request = StreamRequest(
        last_received_event_id=last_received_event_id,
        window_size_increment=window_size_increment
    )

    factory.handle_valid_request(connection, request)

    assert connection.sendMessage.call_count == expected_events_sent
    assert connection.last_received_event_id == last_received_event_id
    assert connection.available_window_size == starting_window_size + window_size_increment - expected_events_sent


def test_handle_invalid_request():
    factory = _get_factory()
    connection = EventWebsocketProtocol()
    connection.sendMessage = Mock()
    validation_error = Mock(spec_set=ValidationError)
    validation_error.errors = Mock(return_value=[])

    factory.handle_invalid_request(connection, validation_error)

    connection.sendMessage.assert_called_once()


def _get_factory(n_starting_events: int = 0) -> EventWebsocketFactory:
    event_storage = _get_event_storage(n_starting_events)

    return EventWebsocketFactory(event_storage)


def _get_event_storage(n_starting_events: int) -> EventStorage:
    event_storage = Mock(spec_set=EventStorage)
    event_storage.get_last_event = Mock(
        return_value=None if n_starting_events == 0 else _create_event(n_starting_events)
    )
    event_storage.iter_from_event = Mock(
        side_effect=lambda from_event_id: _iter_from_event(from_event_id, n_starting_events)
    )

    return event_storage


def _iter_from_event(from_event_id: int, n_starting_events: int) -> Iterator[BaseEvent]:
    return (_create_event(event_id) for event_id in range(from_event_id, n_starting_events))


def _create_event(event_id: int) -> BaseEvent:
    return BaseEvent(
        peer_id='123',
        id=event_id,
        timestamp=123456,
        type='type',
        data={}
    )
