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
