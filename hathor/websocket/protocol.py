# Copyright 2021 Hathor Labs
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

from typing import TYPE_CHECKING, Union

from autobahn.twisted.websocket import WebSocketServerProtocol
from structlog import get_logger

if TYPE_CHECKING:
    from hathor.websocket.factory import HathorAdminWebsocketFactory

logger = get_logger()


class HathorAdminWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol to communicate with admin frontend

        We save a set of connections that we have opened so we
        can send the data update to the clients
    """

    def __init__(self, factory: 'HathorAdminWebsocketFactory') -> None:
        self.log = logger.new()
        self.factory = factory
        self.subscribed_to: set[str] = set()
        super().__init__()

    def onConnect(self, request):
        self.log.info('connection opened, starting handshake...', request=request)

    def onOpen(self) -> None:
        self.factory.on_client_open(self)
        self.log.info('connection established')

    def onClose(self, wasClean, code, reason):
        self.factory.on_client_close(self)
        self.log.info('connection closed', reason=reason)

    def onMessage(self, payload: Union[bytes, str], isBinary: bool) -> None:
        self.log.debug('new message', payload=payload.hex() if isinstance(payload, bytes) else payload)
        self.factory.handle_message(self, payload)
