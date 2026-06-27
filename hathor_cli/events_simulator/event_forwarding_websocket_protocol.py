# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
