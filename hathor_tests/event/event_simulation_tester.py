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

from twisted.internet.testing import StringTransport

from hathor.event.websocket import EventWebsocketProtocol
from hathor.event.websocket.request import Request
from hathor.event.websocket.response import EventResponse, InvalidRequestResponse
from hathor.p2p.peer import PrivatePeer
from hathor.transaction.util import unpack, unpack_len
from hathor.util import json_loadb
from hathor_tests.simulation.base import SimulatorTestCase


class BaseEventSimulationTester(SimulatorTestCase):
    def setUp(self) -> None:
        super().setUp()
        self._prepare(reward_spend_min_blocks=1)  # to make tests run quicker

    def _prepare(self, reward_spend_min_blocks: int) -> None:
        peer = PrivatePeer.auto_generated()
        builder = (
            self.simulator.get_default_builder()
            .set_peer(peer)
            .enable_event_queue()
            .set_settings(
                self._settings.model_copy(
                    update={"REWARD_SPEND_MIN_BLOCKS": reward_spend_min_blocks}
                )
            )
        )
        artifacts = self.simulator.create_artifacts(builder)

        self.peer_id: str = str(peer.id)
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
        return list(map(EventResponse.model_validate, self._get_transport_messages()))

    def _get_error_response(self) -> InvalidRequestResponse:
        responses = self._get_transport_messages()
        assert len(responses) == 1
        return InvalidRequestResponse.model_validate(responses[0])

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
