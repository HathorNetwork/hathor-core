from twisted.test import proto_helpers


def resolve_block_bytes(block_bytes):
    """ From block bytes we create a block and resolve pow
        Return block bytes with hash and nonce after pow
        :rtype: bytes
    """
    from hathor.transaction import Block
    import base64
    block_bytes = base64.b64decode(block_bytes)
    block = Block.create_from_struct(block_bytes)
    block.weight = 10
    block.resolve()
    return block.get_struct()


class FakeConnection:
    def __init__(self, server_manager, client_manager):
        self.server_manager = server_manager
        self.client_manager = client_manager

        self.proto1 = server_manager.server_factory.buildProtocol(('127.0.0.1', 0))
        self.proto2 = client_manager.client_factory.buildProtocol(('127.0.0.1', 0))

        self.tr1 = proto_helpers.StringTransport()
        self.tr2 = proto_helpers.StringTransport()

        self.proto1.makeConnection(self.tr1)
        self.proto2.makeConnection(self.tr2)

    def run_one_step(self, debug=False):
        line1 = self.tr1.value()
        line2 = self.tr2.value()

        if debug:
            print('--')
            print('line1', line1)
            print('line2', line2)
            print('--')

        self.tr1.clear()
        self.tr2.clear()

        if line1:
            self.proto2.dataReceived(line1)
        if line2:
            self.proto1.dataReceived(line2)

    def disconnect(self, reason):
        self.tr1.loseConnection()
        self.proto1.connectionLost(reason)
        self.tr2.loseConnection()
        self.proto2.connectionLost(reason)
