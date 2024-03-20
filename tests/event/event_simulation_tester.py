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

from json import JSONDecodeError
from typing import Any, Iterable
from unittest.mock import Mock

import pytest
from twisted.internet.testing import StringTransport

from hathor.builder import Builder
from hathor.event.websocket import EventWebsocketProtocol
from hathor.event.websocket.request import Request
from hathor.event.websocket.response import EventResponse, InvalidRequestResponse
from hathor.p2p.peer_id import PeerId
from hathor.transaction.util import unpack, unpack_len
from hathor.util import json_loadb
from tests.simulation.base import SimulatorTestCase
from tests.utils import HAS_ROCKSDB


class BaseEventSimulationTester(SimulatorTestCase):
    builder: Builder

    def _create_artifacts(self) -> None:
        peer_id = PeerId()
        builder = self.builder.set_peer_id(peer_id) \
            .disable_full_verification() \
            .enable_event_queue()
        artifacts = self.simulator.create_artifacts(builder)

        assert peer_id.id is not None
        self.peer_id: str = peer_id.id
        self.manager = artifacts.manager
        self.manager.allow_mining_without_peers()
        self.settings = artifacts.settings

        event_ws_factory = self.manager._event_manager._event_ws_factory
        assert event_ws_factory is not None
        event_ws_factory.openHandshakeTimeout = 0

        self.protocol = event_ws_factory.buildProtocol(addr=Mock())
        self.transport = StringTransport()
        self.protocol.makeConnection(self.transport)
        self.protocol.state = EventWebsocketProtocol.STATE_OPEN
        self.protocol.onOpen()

    def _send_request(self, request: Request) -> None:
        self.protocol.onMessage(
            payload=request.json_dumpb(),
            isBinary=False
        )

    def _get_success_responses(self) -> list[EventResponse]:
        return list(map(EventResponse.parse_obj, self._get_transport_messages()))

    def _get_error_response(self) -> InvalidRequestResponse:
        responses = self._get_transport_messages()
        assert len(responses) == 1
        return InvalidRequestResponse.parse_obj(responses[0])

    def _get_transport_messages(self) -> list[dict[str, Any]]:
        values = self.transport.value()
        result = self._decode_values(values)

        self.transport.clear()

        return list(result)

    @staticmethod
    def _decode_values(values: bytes) -> Iterable[dict[str, Any]]:
        buf = values

        while buf:
            try:
                (_, _, value_length), new_buf = unpack('!BBH', buf)
                value, new_buf = unpack_len(value_length, new_buf)
                yield json_loadb(value)
            except JSONDecodeError:
                (_, value_length), new_buf = unpack('!BB', buf)
                value, new_buf = unpack_len(value_length, new_buf)
                yield json_loadb(value)

            buf = new_buf


class MemoryEventSimulationTester(BaseEventSimulationTester):
    def setUp(self) -> None:
        super().setUp()
        self.builder = self.simulator.get_default_builder()
        self._create_artifacts()


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class RocksDBEventSimulationTester(BaseEventSimulationTester):
    def setUp(self) -> None:
        super().setUp()
        import tempfile

        directory = tempfile.mkdtemp()
        self.tmpdirs.append(directory)

        self.builder = self.simulator.get_default_builder().use_rocksdb(path=directory)
        self._create_artifacts()
