# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Any

from twisted.internet.interfaces import IAddress

from hathor.event.websocket import EventWebsocketFactory  # skip-cli-import-custom-check

if TYPE_CHECKING:
    from hathor_cli.events_simulator.event_forwarding_websocket_protocol import EventForwardingWebsocketProtocol
    from hathor.simulator import Simulator


class EventForwardingWebsocketFactory(EventWebsocketFactory):
    def __init__(self, simulator: 'Simulator', *args: Any, **kwargs: Any) -> None:
        self._simulator = simulator
        super().__init__(*args, **kwargs)

    def buildProtocol(self, _: IAddress) -> 'EventForwardingWebsocketProtocol':
        from hathor_cli.events_simulator.event_forwarding_websocket_protocol import EventForwardingWebsocketProtocol
        protocol = EventForwardingWebsocketProtocol(self._simulator)
        protocol.factory = self
        return protocol
