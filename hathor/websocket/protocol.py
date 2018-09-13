from autobahn.twisted.websocket import WebSocketServerProtocol


class HathorAdminWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol to communicate with admin frontend

        We save a set of connections that we have opened so we
        can send the data update to the clients
    """
    def __init__(self, factory):
        self.factory = factory
        super().__init__()

    def onConnect(self, request):
        print("Client connecting: {0}".format(request.peer))

    def onOpen(self):
        self.factory.connections.add(self)
        print("WebSocket connection open.")

    def onClose(self, wasClean, code, reason):
        self.factory.connections.remove(self)
        print("Websocket closed: {}".format(reason))
