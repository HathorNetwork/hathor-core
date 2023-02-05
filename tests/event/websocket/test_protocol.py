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

from unittest.mock import Mock

import pytest

from hathor.event.websocket import EventWebsocketFactory
from hathor.event.websocket.protocol import EventWebsocketProtocol
from hathor.event.websocket.request import StreamRequest


@pytest.fixture
def factory():
    return Mock(spec_set=EventWebsocketFactory)


def test_init():
    protocol = EventWebsocketProtocol()

    assert protocol.last_received_event_id is None
    assert protocol.available_window_size == 0


def test_next_event_id():
    protocol = EventWebsocketProtocol()

    assert protocol.next_event_id == 0

    protocol.last_received_event_id = 5

    assert protocol.next_event_id == 6


def test_on_open(factory):
    protocol = EventWebsocketProtocol()
    protocol.factory = factory

    protocol.onOpen()

    factory.register.assert_called_once_with(protocol)


def test_on_close(factory):
    protocol = EventWebsocketProtocol()
    protocol.factory = factory

    protocol.onClose(True, 1, 'reason')

    factory.unregister.assert_called_once_with(protocol)


def test_on_message(factory):
    payload = b'{"last_received_event_id": 100, "window_size_increment": "50"}'
    request = StreamRequest(last_received_event_id=100, window_size_increment=50)
    protocol = EventWebsocketProtocol()
    protocol.factory = factory

    protocol.onMessage(payload, False)

    factory.handle_request.assert_called_once_with(protocol, request)
