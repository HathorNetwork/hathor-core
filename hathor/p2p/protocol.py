# encoding: utf-8

from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import Protocol
from twisted.internet.task import LoopingCall
from twisted.python import log
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.twisted.websocket import WebSocketClientProtocol

from hathor.p2p.peer_id import PeerId
from hathor.transaction import Transaction, Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
import hathor

from enum import Enum
import json
import time
import uuid
import base64


class HathorProtocol(Protocol):
    """ Implements Hathor Protocol. An instance of this class is
    created for each connection.

    When the connection is established, the protocol waits for a
    HELLO message, which will identify the application and give a
    nonce value.

    After receiving a HELLO message, the peer must reply with a PEER-ID
    message, which will identity the peer through its id, public key,
    and endpoints. There must be a signature of the nonce value which
    will be checked against the public key.

    After the PEER-ID message, the peer is ready to communicate.

    The available states are listed in PeerState class.
    The available commands are listed in the ProtocolCommand class.
    """

    class PeerState(Enum):
        HELLO = 'HELLO'
        PEER_ID = 'PEER-ID'
        READY = 'READY'

    class ProtocolCommand(Enum):
        # ---
        # Peer-to-peer Control Messages
        # ---
        # Identifies the app and network the peer would like to connect to.
        HELLO = 'HELLO'

        # Identifies the peer.
        PEER_ID = 'PEER-ID'

        # Request a list of peers.
        GET_PEERS = 'GET-PEERS'

        # Usually it is a response to a GET-PEERS command. But it can be sent
        # without request when a new peer connects.
        PEERS = 'PEERS'

        # Ping is used to prevent an idle connection.
        PING = 'PING'

        # Pong is a response to a PING command.
        PONG = 'PONG'

        # Notifies an error.
        ERROR = 'ERROR'

        # ---
        # Hathor Specific Messages
        # ---
        GET_DATA = 'GET-DATA'  # Request the data for a specific transaction.
        DATA = 'DATA'          # Send the data for a specific transaction.

        GET_TIPS = 'GET-TIPS'

        GET_BLOCKS = 'GET-BLOCKS'  # Request a list of hashes for blocks. Payload is the current latest block.
        BLOCKS = 'BLOCKS'          # Send a list of hashes for blocks. Payload is a list of hashes.

        HASHES = 'HASHES'

        # Request the height of the last known block.
        GET_BEST_HEIGHT = 'GET-BEST-HEIGHT'

        # Send the height of the last known block.
        BEST_HEIGHT = 'BEST-HEIGHT'

    def __init__(self, factory):
        self.factory = factory

        # The peer on the other side of the connection.
        self.peer = None

        # It triggers an event to send a ping message if necessary.
        self.lc_ping = None

        # The last time a message has been received from this peer.
        self.last_message = 0

        # The last time a request was send to this peer.
        self.last_request = 0

        # The current state of the connection.
        self.state = None

    def connectionMade(self):
        """ Executed when the connection is established.
        """
        remote = self.transport.getPeer()
        # local = self.transport.getHost()

        # The initial state is HELLO.
        self.state = self.PeerState.HELLO

        # The nonce that was sent to the peer to check its identity.
        self.hello_nonce = str(uuid.uuid4())

        # After a connection is made, we just send a HELLO message.
        self.send_hello()
        log.msg('HathorLineReceiver.connectionMade()', remote)

    def connectionLost(self, reason):
        """ Executed when the connection is lost.
        """
        remote = self.transport.getPeer()
        if self.peer:
            self.factory.connected_peers.pop(self.peer.id, None)
        if self.lc_ping:
            self.lc_ping.stop()
        print('Connection lost:', remote)

    def send_message(self, cmd, payload):
        """ A generic message which must be implemented to send a message
        to the peer. It depends on the underlying protocol in which
        HathorProtocol is running.
        """
        raise NotImplemented()

    def recv_message(self, cmd, payload):
        """ Executed when a new message arrives.
        """
        self.last_message = time.time()

        if cmd == self.ProtocolCommand.ERROR:
            self.handle_error(payload)
            return

        if self.state == self.PeerState.HELLO:
            # At first, only the HELLO command is allowed.
            if cmd == self.ProtocolCommand.HELLO:
                self.handle_hello(payload)
            else:
                self.send_error_and_close_connection('Only HELLO message is valid. Invalid command: {}'.format(cmd))
            return

        if self.state == self.PeerState.PEER_ID:
            # After the hello, the peer must identify itself with a PEER-ID command.
            if cmd == self.ProtocolCommand.PEER_ID:
                self.handle_peer_id(payload)
            else:
                self.send_error_and_close_connection('Only PEER-ID message is valid. Invalid command: {}'.format(cmd))
            return

        # Then, when the peer is ready to communicate, the other commands are available.
        cmd_map = {
            # p2p control messages
            self.ProtocolCommand.PING: self.handle_ping,
            self.ProtocolCommand.PONG: self.handle_pong,
            self.ProtocolCommand.GET_PEERS: self.handle_get_peers,
            self.ProtocolCommand.PEERS: self.handle_peers,

            # hathor messages
            self.ProtocolCommand.GET_DATA: self.handle_get_data,
            self.ProtocolCommand.DATA: self.handle_data,
            self.ProtocolCommand.GET_BLOCKS: self.handle_get_blocks,
            self.ProtocolCommand.BLOCKS: self.handle_blocks,
            self.ProtocolCommand.GET_BEST_HEIGHT: self.handle_get_best_height,
            self.ProtocolCommand.BEST_HEIGHT: self.handle_best_height,
        }

        fn = cmd_map.get(cmd)
        if fn is not None:
            try:
                fn(payload)
            except Exception as e:
                print('Unhandled Exception:', e)
                raise
        else:
            print('Command invalid:', cmd)

    def send_error(self, msg):
        """ Send an error message to the peer.
        """
        print('Sending error message:', msg)
        self.send_message(self.ProtocolCommand.ERROR, msg)

    def send_error_and_close_connection(self, msg):
        """ Send an ERROR message to the peer, and then closes the connection.
        """
        self.send_error(msg)
        self.transport.loseConnection()

    def handle_error(self, payload):
        """ Executed when an ERROR command is received.
        """
        print('ERROR', payload)

    def send_get_data(self, hash_hex):
        """ Send a GET-DATA message, requesting the data of a given hash.
        """
        print('send_get_data', hash_hex)
        self.send_message(self.ProtocolCommand.GET_DATA, hash_hex)

    def handle_get_data(self, payload):
        hash_hex = payload
        print('handle_get_data', hash_hex)
        try:
            tx = self.factory.tx_storage.get_transaction_by_hash(hash_hex)
            self.send_data(tx)
        except TransactionDoesNotExist:
            # TODO Send NOT-FOUND?
            self.send_data('')
        except Exception as e:
            print(e)

    def send_data(self, tx):
        payload_type = 'tx' if not tx.is_block else 'block'
        payload = base64.b64encode(tx.get_struct()).decode('ascii')
        self.send_message(self.ProtocolCommand.DATA, '{}:{}'.format(payload_type, payload))

    def handle_data(self, payload):
        if not payload:
            return
        payload_type, _, payload = payload.partition(':')
        data = base64.b64decode(payload)
        if payload_type == 'tx':
            tx = Transaction.create_from_struct(data)
        elif payload_type == 'block':
            tx = Block.create_from_struct(data)
        else:
            raise ValueError('Unknown payload load')

        if self.factory.tx_storage.get_genesis_by_hash_bytes(tx.hash):
            print('!!! WE JUST GOT A GENESIS')
            return
        self.factory.on_new_tx(tx, conn=self)

    def send_get_best_height(self):
        self.send_message(self.ProtocolCommand.GET_BEST_HEIGHT)

    def handle_get_best_height(self, unused_payload):
        print('handle_get_best_height')
        payload = self.factory.tx_storage.get_best_height()
        self.send_message(self.ProtocolCommand.BEST_HEIGHT, str(payload))

    def handle_best_height(self, payload):
        print('handle_best_height:', payload)
        best_height = int(payload)
        self.factory.on_best_height(best_height, conn=self)

    def send_get_blocks(self):
        payload = self.factory.tx_storage.get_latest_block().hash_hex
        self.send_message(self.ProtocolCommand.GET_BLOCKS, payload)

    def handle_get_blocks(self, payload):
        print('handle_get_blocks;', payload)
        block_hashes = self.factory.tx_storage.get_block_hashes_after(payload)
        block_hashes_hex = [x.hex() for x in block_hashes]
        output_payload = json.dumps(block_hashes_hex)
        self.send_message(self.ProtocolCommand.BLOCKS, output_payload)

    def handle_blocks(self, payload):
        print('handle_blocks')
        block_hashes = json.loads(payload)
        self.factory.on_block_hashes_received(block_hashes, conn=self)

    def send_get_peers(self):
        """ Send a GET-PEERS command, requesting a list of nodes.
        """
        self.send_message(self.ProtocolCommand.GET_PEERS)

    def handle_get_peers(self, payload):
        """ Executed when a GET-PEERS command is received. It just responds with
        a list of all known peers.
        """
        self.send_peers()

    def send_peers(self):
        """ Send a PEERS command with a list of all known peers.
        """
        peers = []
        for conn in self.factory.connected_peers.values():
            peers.append({
                'id': conn.peer.id,
                'entrypoints': conn.peer.entrypoints,
                'last_message': conn.last_message,
            })
        self.send_message(self.ProtocolCommand.PEERS, json.dumps(peers))
        print('Peers: %s' % str(peers))

    def handle_peers(self, payload):
        """ Executed when a PEERS command is received. It updates the list
        of known peers (and tries to connect to new ones).
        """
        received_peers = json.loads(payload)
        for data in received_peers:
            peer = PeerId.create_from_json(data)
            peer.validate()
            self.factory.update_peer(peer)
        remote = self.transport.getPeer()
        print(remote, 'PEERS', payload)

    def send_hello(self):
        """ Send a HELLO message, identifying the app and giving a `nonce`
        value which must be signed in the PEER-ID response to ensure the
        identity of the peer.
        """
        remote = self.transport.getPeer()
        data = {
            'app': 'Hathor v{}'.format(hathor.__version__),
            'network': self.factory.network,
            'remote_address': '{}:{}'.format(remote.host, remote.port),
            'nonce': self.hello_nonce,
        }
        self.send_message(self.ProtocolCommand.HELLO, json.dumps(data))

    def handle_hello(self, payload):
        """ Executed when a HELLO message is received. It basically
        checks the application compatibility.
        """
        try:
            data = json.loads(payload)
        except ValueError:
            self.send_error_and_close_connection('Invalid payload.')
            return

        if {'app', 'network', 'remote_address', 'nonce'} != set(data):
            self.send_error_and_close_connection('Invalid payload.')
            return

        app = 'Hathor v{}'.format(hathor.__version__)
        if data['app'] != app:
            print('WARNING Different app versions:', data['app'])

        if data['network'] != self.factory.network:
            self.send_error_and_close_connection('Wrong network.')
            return

        nonce = data['nonce']

        self.state = self.PeerState.PEER_ID
        self.send_peer_id(nonce)

    def send_peer_id(self, nonce):
        """ Send a PEER-ID message, identifying the peer. It goes with a
        signature of the `nonce` value received in the HELLO message.
        """
        my_peer = self.factory.my_peer
        hello = {
            'id': my_peer.id,
            'pubKey': my_peer.get_public_key(),
            'entrypoints': my_peer.entrypoints,
            'nonce': nonce,
            'signature': base64.b64encode(my_peer.sign(nonce.encode('ascii'))).decode('ascii'),
        }
        self.send_message(self.ProtocolCommand.PEER_ID, json.dumps(hello))

    def handle_peer_id(self, payload):
        """ Executed when a PEER-ID is received. It basically checks
        the identity of the peer. Only after this step, the peer connection
        is considered established and ready to communicate.
        """
        remote = self.transport.getPeer()
        print(remote, 'HELLO', payload)
        data = json.loads(payload)

        if self.hello_nonce != data['nonce']:
            self.send_error_and_close_connection('Invalid nonce.')
            return

        peer = PeerId.create_from_json(data)
        peer.validate()

        if peer.id == self.factory.my_peer.id:
            self.send_error_and_close_connection('Are you my clone?!')
            return

        signature = base64.b64decode(data['signature'])
        if not peer.verify_signature(signature, self.hello_nonce.encode('ascii')):
            self.send_error_and_close_connection('Invalid signature.')
            return

        if peer.id in self.factory.connected_peers:
            self.send_error_and_close_connection('We are already connected.')
            return

        # If it gets here, the peer is validated, and we are ready to start communicating.
        # TODO Move it to a new method (`on_ready`?)
        self.state = self.PeerState.READY
        self.factory.peer_storage.add_or_merge(peer)

        self.peer = peer
        self.factory.connected_peers[self.peer.id] = self
        print('factory.connected_peers:' + str(self.factory.connected_peers))

        self.lc_ping = LoopingCall(self.send_ping_if_necessary)
        self.lc_ping.start(1)

        self.send_get_peers()
        self.send_get_best_height()

    def send_ping_if_necessary(self):
        """ Send a PING command if the connection has been idle for 3 seconds or more.
        """
        dt = time.time() - self.last_message
        if dt > 3:
            self.send_ping()

    def send_ping(self):
        """ Send a PING command. Usually you would use `send_ping_if_necessary` to
        prevent wasting bandwidth.
        """
        self.send_message(self.ProtocolCommand.PING)

    def send_pong(self):
        """ Send a PONG command as a response to a PING command.
        """
        self.send_message(self.ProtocolCommand.PONG)

    def handle_ping(self, payload):
        """ Executed when a PING command is received. It responds with a
        PONG message.
        """
        self.send_pong()

    def handle_pong(self, payload):
        """ Executed when a PONG message is received. It only updates
        the last time a message has been received by this peer.
        """
        self.last_message = time.time()


class HathorLineReceiver(LineReceiver, HathorProtocol):
    """ Implements HathorProtocol in a LineReceiver protocol.
    It is simply a TCP connection which sends one message per line.
    """
    def connectionMade(self):
        self.setLineMode()
        super(HathorLineReceiver, self).connectionMade()

    def lineReceived(self, line):
        line = line.decode('utf-8')
        msgtype, _, msgdata = line.partition(' ')

        try:
            cmd = self.ProtocolCommand(msgtype)
            self.recv_message(cmd, msgdata)
        except ValueError:
            self.transport.loseConnection()

    def send_message(self, cmd, payload=None):
        if isinstance(cmd, self.ProtocolCommand):
            cmd = cmd.value
        if payload:
            line = '{} {}'.format(cmd, payload).encode('utf-8')
        else:
            line = cmd.encode('utf-8')
        self.sendLine(line)


class HathorWebSocketServerProtocol(WebSocketServerProtocol, HathorProtocol):
    def onMessage(self, payload, isBinary):
        pass


class HathorWebSocketClientProtocol(WebSocketClientProtocol, HathorProtocol):
    def onMessage(self, payload, isBinary):
        pass
