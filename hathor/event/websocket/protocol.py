# Copyright 2022 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from dataclasses import dataclass

from typing import Set, Union

from autobahn.twisted.websocket import WebSocketServerFactory, WebSocketServerProtocol


class StreamingState:
    # def enter(
    pass


class Initial(StreamingState):
    # def handle_message(self,
    pass


@dataclass
class EventStreaming(StreamingState):
    last_event: int


class HathorEventWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol, basically forwards some events to the Websocket factory.
    """

    def __init__(self, factory: WebSocketServerFactory):
        self.factory = factory
        self.state: StreamingState = Initial()
        super().__init__()

    def onConnect(self, request):
        self.log.info('connection opened to the event websocket, starting handshake...', request=request)

    def onOpen(self) -> None:
        self.log.info('connection established to the event websocket')
        self.factory.on_client_open(self)

    def onClose(self, wasClean, code, reason):
        self.log.info('connection closed to the event websocket', reason=reason)
        self.factory.on_client_close(self)

    def onMessage(self, payload: Union[bytes, str], isBinary: bool) -> None:
        self.log.debug('message', payload=payload.hex() if isinstance(payload, bytes) else payload)
        self.factory.handle_message(self, payload)
