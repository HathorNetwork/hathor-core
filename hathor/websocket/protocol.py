from typing import Set, Union

from autobahn.twisted.websocket import WebSocketServerProtocol
from structlog import get_logger

logger = get_logger()


class HathorAdminWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol to communicate with admin frontend

        We save a set of connections that we have opened so we
        can send the data update to the clients
    """

    def __init__(self, factory):
        self.log = logger.new()
        self.factory = factory
        self.subscribed_to: Set[str] = set()
        super().__init__()

    def onConnect(self, request):
        self.log.info('connect', request=request)

    def onOpen(self) -> None:
        self.factory.connections.add(self)
        self.log.info('connection opened')

    def onClose(self, wasClean, code, reason):
        self.factory.connection_closed(self)
        self.log.info('connection closed', reason=reason)

    def onMessage(self, payload: Union[bytes, str], isBinary: bool) -> None:
        self.log.debug('new message', payload=payload.hex() if isinstance(payload, bytes) else payload)
        self.factory.handle_message(self, payload)
