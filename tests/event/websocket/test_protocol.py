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
from hathor.util import json_dumpb


@pytest.fixture
def factory():
    return Mock(spec_set=EventWebsocketFactory)


def test_init():
    protocol = EventWebsocketProtocol()

    assert protocol.last_received_event_id is None
    assert protocol.window_size == 0


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


@pytest.mark.parametrize('last_received_event_id', [None, 0, 1, 10])
@pytest.mark.parametrize('window_size', [0, 1, 10])
def test_on_valid_message(factory, last_received_event_id, window_size):
    payload = {
        'last_received_event_id': last_received_event_id,
        'window_size': window_size
    }
    request = StreamRequest(last_received_event_id=last_received_event_id, window_size=window_size)
    protocol = EventWebsocketProtocol()
    protocol.factory = factory

    protocol.onMessage(json_dumpb(payload), False)

    factory.handle_valid_request.assert_called_once_with(protocol, request)


@pytest.mark.parametrize(
    ['last_received_event_id', 'window_size'],
    [(-1, 0), (0, -1)]
)
def test_on_invalid_message(factory, last_received_event_id, window_size):
    payload = {
        'last_received_event_id': last_received_event_id,
        'window_size': window_size
    }
    protocol = EventWebsocketProtocol()
    protocol.factory = factory

    protocol.onMessage(json_dumpb(payload), False)

    factory.handle_invalid_request.assert_called_once()
