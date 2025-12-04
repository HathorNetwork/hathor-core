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

from typing import TYPE_CHECKING

from autobahn.websocket import ConnectionRequest

from hathor.event.websocket import EventWebsocketProtocol  # skip-cli-import-custom-check

if TYPE_CHECKING:
    from hathor_cli.events_simulator.event_forwarding_websocket_factory import EventForwardingWebsocketFactory
    from hathor.simulator import Simulator


class EventForwardingWebsocketProtocol(EventWebsocketProtocol):
    factory: 'EventForwardingWebsocketFactory'

    def __init__(self, simulator: 'Simulator') -> None:
        self._simulator = simulator
        super().__init__()

    def onConnect(self, request: ConnectionRequest) -> None:
        super().onConnect(request)
        self._simulator.run(60)

    def onOpen(self) -> None:
        super().onOpen()
        self._simulator.run(60)

    def onClose(self, wasClean: bool, code: int, reason: str) -> None:
        super().onClose(wasClean, code, reason)
        self._simulator.run(60)

    def onMessage(self, payload: bytes, isBinary: bool) -> None:
        super().onMessage(payload, isBinary)
        self._simulator.run(60)
