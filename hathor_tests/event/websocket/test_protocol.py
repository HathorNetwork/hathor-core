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

from typing import Optional
from unittest.mock import ANY, Mock, patch

import pytest
from autobahn.websocket import ConnectionRequest

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_type import EventType
from hathor.event.websocket import EventWebsocketFactory
from hathor.event.websocket.protocol import EventWebsocketProtocol
from hathor.event.websocket.response import EventResponse, InvalidRequestType
from hathor_tests.utils import EventMocker


@pytest.fixture
def factory() -> Mock:
    return Mock(spec_set=EventWebsocketFactory)


def test_init() -> None:
    protocol = EventWebsocketProtocol()

    assert protocol.client_peer is None
    assert protocol._last_sent_event_id is None
    assert protocol._ack_event_id is None
    assert protocol._window_size == 0
    assert not protocol._stream_is_active


def test_next_expected_event_id() -> None:
    protocol = EventWebsocketProtocol()

    assert protocol.next_expected_event_id() == 0

    protocol._last_sent_event_id = 5

    assert protocol.next_expected_event_id() == 6


def test_on_connect() -> None:
    protocol = EventWebsocketProtocol()
    request = Mock(spec_set=ConnectionRequest)
    request.peer = 'some_peer'

    protocol.onConnect(request)

    assert protocol.client_peer == 'some_peer'


def test_on_open(factory: Mock) -> None:
    protocol = EventWebsocketProtocol()
    protocol.factory = factory

    protocol.onOpen()

    factory.register.assert_called_once_with(protocol)


def test_on_close(factory: Mock) -> None:
    protocol = EventWebsocketProtocol()
    protocol.factory = factory

    protocol.onClose(True, 1, 'reason')

    factory.unregister.assert_called_once_with(protocol)


def test_send_event_response() -> None:
    protocol = EventWebsocketProtocol()
    protocol.sendMessage = Mock()
    response = EventResponse(
        peer_id='my_peer_id',
        network='my_network',
        event=BaseEvent(
            id=10,
            timestamp=123,
            type=EventType.VERTEX_METADATA_CHANGED,
            data=EventMocker.tx_data
        ),
        latest_event_id=10,
        stream_id='stream_id'
    )

    protocol.send_event_response(response)

    expected_payload = (b'{"type":"EVENT","peer_id":"my_peer_id","network":"my_network","event":{"id":10,'
                        b'"timestamp":123.0,"type":"VERTEX_METADATA_CHANGED","data":{"hash":"abc","nonce":123,'
                        b'"timestamp":456,"signal_bits":0,"version":1,"weight":10.0,"inputs":[],"outputs":[],'
                        b'"parents":[],'
                        b'"tokens":[],"token_name":null,"token_symbol":null,"aux_pow":null,"headers":[],'
                        b'"name":"tx name","metadata":{"hash":"abc",'
                        b'"spent_outputs":[],"conflict_with":[],"voided_by":[],"received_by":[],'
                        b'"twins":[],"accumulated_weight":10.0,"score":20.0,"accumulated_weight_raw":"1024",'
                        b'"score_raw":"1048576","first_block":null,"height":100,'
                        b'"validation":"validation","nc_execution":null}},"group_id":null},"latest_event_id":10,'
                        b'"stream_id":"stream_id"}')

    protocol.sendMessage.assert_called_once_with(expected_payload)


@pytest.mark.parametrize('_type', [InvalidRequestType.VALIDATION_ERROR, InvalidRequestType.STREAM_IS_INACTIVE])
@pytest.mark.parametrize('invalid_payload', [None, b'some_payload'])
@pytest.mark.parametrize('error_message', [None, 'some error'])
def test_send_invalid_request_response(
    _type: InvalidRequestType,
    invalid_payload: bytes | None,
    error_message: str | None
) -> None:
    protocol = EventWebsocketProtocol()
    protocol.sendMessage = Mock()

    protocol.send_invalid_request_response(_type, invalid_payload, error_message)

    invalid_request = "null" if invalid_payload is None else f'"{invalid_payload.decode("utf8")}"'
    error_message = "null" if error_message is None else f'"{error_message}"'
    expected_payload = f'{{"type":"{_type.value}","invalid_request":{invalid_request},' \
                       f'"error_message":{error_message}}}'

    protocol.sendMessage.assert_called_once_with(expected_payload.encode('utf8'))


@pytest.mark.parametrize(
    [
        'last_sent_event_id',
        'ack_event_id',
        'window_size',
        'stream_is_active',
        'event_id',
        'expected_result',
    ],
    [
        (None, None, 0, False, 0, False),
        (None, None, 0, True, 0, False),
        (None, None, 1, True, 0, True),
        (0, None, 1, False, 1, False),
        (0, None, 1, True, 1, False),
        (0, 0, 1, False, 1, False),
        (0, 0, 1, True, 1, True),
        (1, 0, 1, True, 2, False),
        (1, 0, 2, False, 2, False),
        (1, 0, 2, True, 2, True),
        (2, 2, 3, True, 3, True),
        (3, 2, 3, True, 4, True),
        (4, 2, 3, False, 5, False),
        (4, 2, 3, True, 5, True),
        (4, 2, 3, True, 4, False),
        (5, 2, 3, True, 6, False),
    ]
)
def test_can_receive_event(
    last_sent_event_id: Optional[int],
    ack_event_id: Optional[int],
    window_size: int,
    stream_is_active: bool,
    event_id: int,
    expected_result: bool
) -> None:
    protocol = EventWebsocketProtocol()
    protocol._last_sent_event_id = last_sent_event_id
    protocol._ack_event_id = ack_event_id
    protocol._window_size = window_size
    protocol._stream_is_active = stream_is_active

    result = protocol.can_receive_event(event_id)

    assert result == expected_result


def test_on_valid_stop_message() -> None:
    protocol = EventWebsocketProtocol()
    protocol._stream_is_active = True

    protocol.onMessage(b'{"type": "STOP_STREAM"}', False)

    assert not protocol._stream_is_active


def test_stop_message_on_inactive() -> None:
    protocol = EventWebsocketProtocol()
    protocol.sendMessage = Mock()
    protocol._stream_is_active = False
    payload = b'{"type": "STOP_STREAM"}'

    protocol.onMessage(payload, False)

    response = b'{"type":"STREAM_IS_INACTIVE","invalid_request":"{\\"type\\": \\"STOP_STREAM\\"}",' \
               b'"error_message":null}'
    protocol.sendMessage.assert_called_once_with(response)
    assert not protocol._stream_is_active


@pytest.mark.parametrize(
    ['ack_event_id', 'window_size', 'last_sent_event_id'],
    [
        (0, 0, 0),
        (0, 1, 10),
        (0, 10, 1),
        (1, 0, 1000),
        (10, 0, 10),
    ]
)
def test_on_valid_ack_message(ack_event_id: int, window_size: int, last_sent_event_id: int) -> None:
    protocol = EventWebsocketProtocol()
    protocol._last_sent_event_id = last_sent_event_id
    protocol.factory = Mock()
    protocol.factory.send_next_event_to_connection = Mock()
    protocol._stream_is_active = True
    payload = f'{{"type": "ACK", "ack_event_id": {ack_event_id}, "window_size": {window_size}}}'.encode('utf8')

    protocol.onMessage(payload, False)

    assert protocol._ack_event_id == ack_event_id
    assert protocol._window_size == window_size
    protocol.factory.send_next_event_to_connection.assert_called_once()


@pytest.mark.parametrize(
    ['ack_event_id', 'window_size', 'last_sent_event_id'],
    [
        (0, 0, None),
        (0, 1, None),
        (10, 0, None),
        (10, 1, None),
        (0, 0, 0),
        (0, 1, 10),
        (0, 10, 1),
        (1, 0, 1000),
        (10, 0, 10),
    ]
)
def test_on_valid_start_message(ack_event_id: int, window_size: int, last_sent_event_id: int | None) -> None:
    protocol = EventWebsocketProtocol()
    protocol._last_sent_event_id = last_sent_event_id
    protocol.factory = Mock()
    protocol.factory.send_next_event_to_connection = Mock()
    payload = f'{{"type": "START_STREAM", "last_ack_event_id": {ack_event_id}, "window_size": {window_size}}}'

    protocol.onMessage(payload.encode('utf8'), False)

    assert protocol._ack_event_id == ack_event_id
    assert protocol._window_size == window_size
    assert protocol._last_sent_event_id == ack_event_id
    assert protocol._stream_is_active
    protocol.factory.send_next_event_to_connection.assert_called_once()


def test_ack_message_on_inactive() -> None:
    protocol = EventWebsocketProtocol()
    protocol.sendMessage = Mock()
    protocol._stream_is_active = False
    payload = b'{"type": "ACK", "ack_event_id": 10, "window_size": 10}'

    protocol.onMessage(payload, False)

    response = b'{"type":"STREAM_IS_INACTIVE","invalid_request":"{\\"type\\": \\"ACK\\", \\"ack_event_id\\": 10, ' \
               b'\\"window_size\\": 10}","error_message":null}'
    protocol.sendMessage.assert_called_once_with(response)


def test_start_message_on_active() -> None:
    protocol = EventWebsocketProtocol()
    protocol.sendMessage = Mock()
    protocol._stream_is_active = True
    payload = b'{"type": "START_STREAM", "last_ack_event_id": 10, "window_size": 10}'

    protocol.onMessage(payload, False)

    response = b'{"type":"STREAM_IS_ACTIVE","invalid_request":"{\\"type\\": \\"START_STREAM\\", ' \
               b'\\"last_ack_event_id\\": 10, \\"window_size\\": 10}","error_message":null}'
    protocol.sendMessage.assert_called_once_with(response)


@pytest.mark.parametrize(
    ['_ack_event_id', 'last_sent_event_id', 'ack_event_id', '_type'],
    [
        (1, None, 0, InvalidRequestType.ACK_TOO_SMALL),
        (1, None, 1, InvalidRequestType.ACK_TOO_SMALL),
        (1, 1, 0, InvalidRequestType.ACK_TOO_SMALL),
        (1, 1, 1, InvalidRequestType.ACK_TOO_SMALL),
        (10, None, 5, InvalidRequestType.ACK_TOO_SMALL),
        (10, None, 10, InvalidRequestType.ACK_TOO_SMALL),
        (10, 1, 5, InvalidRequestType.ACK_TOO_SMALL),
        (10, 1, 10, InvalidRequestType.ACK_TOO_SMALL),
        (0, None, 1, InvalidRequestType.ACK_TOO_LARGE),
        (0, 0, 1, InvalidRequestType.ACK_TOO_LARGE),
        (5, None, 10, InvalidRequestType.ACK_TOO_LARGE),
        (5, 1, 10, InvalidRequestType.ACK_TOO_LARGE),
    ]
)
def test_on_invalid_ack_message(
    _ack_event_id: int,
    last_sent_event_id: int | None,
    ack_event_id: int,
    _type: InvalidRequestType,
) -> None:
    protocol = EventWebsocketProtocol()
    protocol._ack_event_id = _ack_event_id
    protocol._last_sent_event_id = last_sent_event_id
    protocol._stream_is_active = True
    payload = f'{{"type": "ACK", "ack_event_id": {ack_event_id}, "window_size": 0}}'.encode('utf8')

    with patch.object(protocol, 'send_invalid_request_response') as mock:
        protocol.onMessage(payload, False)
        mock.assert_called_once_with(_type, payload)


@pytest.mark.parametrize(
    ['_ack_event_id', 'ack_event_id'],
    [
        (0, None),
        (0, None),
        (1, 0),
        (1, 0),
        (10, 5),
        (10, 5),
    ]
)
def test_on_invalid_start_message(_ack_event_id: int, ack_event_id: int | None) -> None:
    protocol = EventWebsocketProtocol()
    protocol._ack_event_id = _ack_event_id
    ack_event_id_str: str = 'null' if ack_event_id is None else f'{ack_event_id}'
    payload = f'{{"type": "START_STREAM", "last_ack_event_id": {ack_event_id_str}, "window_size": 0}}'.encode('utf8')

    with patch.object(protocol, 'send_invalid_request_response') as mock:
        protocol.onMessage(payload, False)
        mock.assert_called_once_with(InvalidRequestType.ACK_TOO_SMALL, payload)


@pytest.mark.parametrize(
    'payload',
    [
        b'{"type": "FAKE_TYPE"}',
        b'{"type": "STOP_STREAM", "fake_prop": 123}',
        b'{"type": "START_STREAM", "last_ack_event_id": "wrong value", "window_size": 10}',
        b'{"type": "START_STREAM", "last_ack_event_id": 0, "window_size": -10}',
        b'{"type": "START_STREAM", "last_ack_event_id": -10, "window_size": 0}',
        b'{"type": "ACK", "ack_event_id": 0, "window_size": "wrong value"}',
        b'{"type": "ACK", "ack_event_id": 0, "window_size": -10}',
        b'{"type": "ACK", "ack_event_id": -10, "window_size": 0}',
    ]
)
def test_validation_error_on_message(payload: bytes) -> None:
    protocol = EventWebsocketProtocol()
    protocol._stream_is_active = False

    with patch.object(protocol, 'send_invalid_request_response') as mock:
        protocol.onMessage(payload, False)
        mock.assert_called_once_with(InvalidRequestType.VALIDATION_ERROR, payload, ANY)
