# encoding: utf-8

from twisted.internet import protocol, reactor, endpoints
from twisted.internet.task import LoopingCall
import twisted.names.client

from hathor.p2p.peer_storage import PeerStorage
from hathor.transaction import Block, TxOutput
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.wallet import Wallet

from math import log
import time
import socket
import random


from hathor.p2p.protocol import HathorLineReceiver
MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver

# from hathor.p2p.protocol import HathorWebSocketServerProtocol, HathorWebSocketClientProtocol
# MyServerProtocol = HathorWebSocketServerProtocol
# MyClientProtocol = HathorWebSocketClientProtocol


class HathorFactory(protocol.Factory):
    """ HathorFactory is used to generate HathorProtocol objects. It stores the network state,
    including the known peers, connected peers, and so on. It basically manages the p2p network.
    """
    def __init__(self, peer_id, network, hostname=None,
                 wallet=None, tx_storage=None, peer_storage=None, default_port=40403):
        """ peer_id: PeerId of this node.
        network: Which network will this node join? Usually either testnet or mainnet.
        hostname: The hostname of this node is used to generate its entrypoints.
        peer_storage: An instance of PeerStorage. It is instanciated by default if it is not given.
        default_port: Network default port, when only peers IP addresses are discovered.
        """
        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.peer_storage = peer_storage or PeerStorage()
        self.tx_storage = tx_storage or TransactionMemoryStorage()
        self.wallet = wallet or Wallet()

        self.my_peer = peer_id
        self.network = network
        self.default_port = default_port

        self.blocks_per_difficulty = 5
        self.avg_time_between_blocks = 12
        self.block_weight = 18

        # A timer to try to reconnect to the disconnect known peers.
        self.lc_reconnect = LoopingCall(self.reconnect_to_all)
        super(HathorFactory, self).__init__()

    def startFactory(self):
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.connected_peers = {}
        self.start_time = time.time()
        self.lc_reconnect.start(5)

    def stopFactory(self):
        self.lc_reconnect.stop()

    def buildProtocol(self, addr):
        return MyServerProtocol(self)

    def propagate_tx(self, tx):
        self.tx_storage.save_transaction(tx)
        self.on_new_tx(tx)
        for conn in self.connected_peers.values():
            conn.send_data(tx)

    def generate_mining_block(self):
        # TODO Cache to prevent unnecessary processing.
        address = self.wallet.get_unused_address(mark_as_used=False)
        # TODO Get maximum allowed amount.
        amount = 10000
        tx_outputs = [
            TxOutput(amount, address)
        ]
        tip_blocks = self.tx_storage.get_tip_blocks()
        tip_txs = self.tx_storage.get_tip_transactions(count=2)
        parents = tip_blocks + tip_txs
        return Block(weight=self.block_weight, outputs=tx_outputs, parents=parents, storage=self.tx_storage)

    def on_new_tx(self, tx, conn=None):
        # XXX What if we receive a genesis?
        if not self.tx_storage.transaction_exists_by_hash_bytes(tx.hash):
            self.tx_storage.save_transaction(tx)

        if tx.is_block:
            count_blocks = self.tx_storage.count_blocks()
            if count_blocks % self.blocks_per_difficulty == 0:
                print('Adjusting difficulty...')
                avg_dt, new_weight = self.calculate_block_difficulty()
                print('Block weight updated: avg_dt={:.2f} target_avg_dt={:.2f} {:6.2f} -> {:6.2f}'.format(
                    avg_dt,
                    self.avg_time_between_blocks,
                    self.block_weight,
                    new_weight
                ))
                self.block_weight = new_weight

        # meta = self.tx_storage.get_metadata_by_hash_bytes(tx.hash)
        # meta.peers.add(conn.peer_id.id)
        # self.tx_storage.save_metadata(meta)

    def calculate_block_difficulty(self):
        blocks = self.tx_storage.get_latest_blocks(self.blocks_per_difficulty)
        dt = blocks[0].timestamp - blocks[-1].timestamp

        new_weight = (
            self.block_weight
            + log(self.avg_time_between_blocks, 2)
            + log(self.blocks_per_difficulty, 2)
            - log(dt, 2)
        )

        avg_dt = float(dt) / self.blocks_per_difficulty
        return avg_dt, new_weight

    def update_peer(self, peer):
        """ Update a peer information in our storage, and instantly attempt to connect
        to it if it is not connected yet.
        """
        if peer.id == self.my_peer.id:
            return
        self.peer_storage.add_or_merge(peer)
        self.connect_to_if_not_connected(peer)

    def reconnect_to_all(self):
        """ It is called by the `lc_reconnect` timer and tries to connect to all known
        peers.
        """
        for peer in self.peer_storage.values():
            self.connect_to_if_not_connected(peer)

    def connect_to_if_not_connected(self, peer):
        """ Attempts to connect if it is not connected to the peer.
        """
        if not peer.entrypoints:
            return
        if peer.id not in self.connected_peers:
            self.connect_to(random.choice(peer.entrypoints))

    def connect_to(self, description):
        """ Attempt to connect to a peer, even if a connection already exists.
        Usually you should call `connect_to_if_not_connected`.
        """
        endpoint = self.clientFromString(description)
        endpoint.connect(self)
        print('Connecting to: {}...'.format(description))

    def serverFromString(self, description):
        """ Return an endpoint which will be used to listen to new connection.
        """
        return endpoints.serverFromString(reactor, description)

    def listen(self, description):
        """ Start to listen to new connection according to the description.

        e.g. description="tcp:8000"
        """
        endpoint = self.serverFromString(description)
        endpoint.listen(self)
        print('Listening to: {}...'.format(description))
        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}:{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)

    def dns_seed_lookup_text(self, host):
        """ Run a DNS lookup for TXT records to discover new peers.
        """
        x = twisted.names.client.lookupText(host)
        x.addCallback(self.on_dns_seed_found)

    def dns_seed_lookup_address(self, host):
        """ Run a DNS lookup for A records to discover new peers.
        """
        x = twisted.names.client.lookupAddress(host)
        x.addCallback(self.on_dns_seed_found_ipv4)

    def dns_seed_lookup_ipv6_address(self, host):
        """ Run a DNS lookup for AAAA records to discover new peers.
        """
        x = twisted.names.client.lookupIPV6Address(host)
        x.addCallback(self.on_dns_seed_found_ipv6)

    def dns_seed_lookup(self, host):
        """ Run a DNS lookup for TXT, A, and AAAA records to discover new peers.
        """
        self.dns_seed_lookup_text(host)
        self.dns_seed_lookup_address(host)
        # self.dns_seed_lookup_ipv6_address(host)

    def clientFromString(self, description):
        """ Return an endpoint which will be used to open a new connection.
        """
        return endpoints.clientFromString(reactor, description)

    def on_dns_seed_found(self, results):
        """ Executed only when a new peer is discovered by `dns_seed_lookup_text`.
        """
        answers, _, _ = results
        for x in answers:
            data = x.payload.data
            for txt in data:
                txt = txt.decode('utf-8')
                try:
                    print('Seed DNS TXT: "{}" found'.format(txt))
                    endpoint = self.clientFromString(txt)
                    endpoint.connect(self)
                except ValueError:
                    print('Seed DNS TXT: Error parsing "{}"'.format(txt))

    def on_dns_seed_found_ipv4(self, results):
        """ Executed only when a new peer is discovered by `dns_seed_lookup_address`.
        """
        answers, _, _ = results
        for x in answers:
            address = x.payload.address
            host = socket.inet_ntoa(address)
            self.connect_to('tcp:{}:{}'.format(host, self.default_port))
            print('Seed DNS A: "{}" found'.format(host))

    def on_dns_seed_found_ipv6(self, results):
        """ Executed only when a new peer is discovered by `dns_seed_lookup_ipv6_address`.
        """
        # answers, _, _ = results
        # for x in answers:
        #     address = x.payload.address
        #     host = socket.inet_ntop(socket.AF_INET6, address)
        raise NotImplemented()
