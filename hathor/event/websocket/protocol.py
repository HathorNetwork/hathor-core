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

from dataclasses import asdict

from typing import Optional, Union

from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.websocket import ConnectionRequest

from hathor.event.websocket.request import Request, RequestError
from hathor.util import json_loadb, json_dumpb


# autobahn.websocket.types.ConnectionRequest


# class StreamingState:
#     # def enter(
#     pass
#
#
# class Initial(StreamingState):
#     # def handle_message(self,
#     pass
#
#
# @dataclass
# class EventStreaming(StreamingState):
#     last_event: int


class HathorEventWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol, basically forwards some events to the Websocket factory.
    """

    client_peer: Optional[str] = None
    streaming_is_active = False
    last_sent_event_id: Optional[int] = None

    def __init__(self):
        super().__init__()
        # self.state: StreamingState = Initial()

    def onConnect(self, request: ConnectionRequest) -> None:
        self.log.info('connection opened to the event websocket, starting handshake...', request=request)
        self.client_peer = request.peer

    def onOpen(self) -> None:
        self.log.info(f'connection established to the event websocket for client peer \'{self.client_peer}\'')
        self.factory.on_client_open(self)

    def onClose(self, wasClean: bool, code: int, reason: str) -> None:
        self.log.info('connection closed to the event websocket for client peer \'{self.client_peer}\'', reason=reason)
        self.factory.on_client_close(self)

    def onMessage(self, payload: Union[bytes, str], isBinary: bool) -> None:
        self.log.debug('message', payload=payload.hex() if isinstance(payload, bytes) else payload)

        json = json_loadb(payload)
        request = Request.from_dict(json)

        match request:
            case Request():
                self.factory.handle_request(self, request)
            case RequestError():
                self.factory.handle_request_error(self, request)

    def _update_last_sent_event_id(self, event_id: int) -> None:
        last_sent_event_id = self.last_sent_event_id or event_id
        self.last_sent_event_id = max(last_sent_event_id, event_id)
