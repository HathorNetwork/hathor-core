from autobahn.twisted.websocket import WebSocketServerProtocol
from twisted.logger import Logger


class HathorAdminWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol to communicate with admin frontend

        We save a set of connections that we have opened so we
        can send the data update to the clients
    """
    log = Logger()

    def __init__(self, factory):
        self.factory = factory
        super().__init__()

    def onConnect(self, request):
        self.log.info('Client connecting: {request.peer}', request=request)

    def onOpen(self):
        self.factory.connections.add(self)
        self.log.info('WebSocket connection open.')

    def onClose(self, wasClean, code, reason):
        self.factory.connections.remove(self)
        self.log.info('Websocket closed: {reason}', reason=reason)

    def onMessage(self, payload, isBinary):
        self.factory.handle_message(self, payload)
