# encoding: utf-8

from twisted.internet import reactor, endpoints
from twisted.internet.task import LoopingCall
import twisted.names.client

from hathor.p2p.peer_storage import PeerStorage
from hathor.transaction import Block, TxOutput
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.wallet import Wallet

from collections import defaultdict
from enum import Enum
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


def generate_privkey_crt_pem():
    """ Generates a new certificate with a new private key. This certificate is
    used only for TLS connection, and won't be used to identify the peer.

    Adapted from:
    https://github.com/twisted/twisted/blob/trunk/src/twisted/test/server.pem
    """
    from datetime import datetime

    from OpenSSL.crypto import FILETYPE_PEM, TYPE_RSA, X509, PKey, dump_privatekey, dump_certificate

    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    cert = X509()

    # It is optional to have a subject and an issue in a certificate.
    # It works with and without these fields.
    # issuer = cert.get_issuer()
    # subject = cert.get_subject()
    # for dn in [issuer, subject]:
    #     dn.C = b'XX'   # Country
    #     dn.ST = b'XX'  # State or Province
    #     dn.L = b'XX'   # Locality
    #     dn.CN = b'testnet.hathor.network'  # Common Name
    #     dn.O = b'Hathor Network'  # noqa: E741 ambiguous variable name 'O'
    #     dn.OU = b'testnet'   # Organization Unit
    #     dn.emailAddress = b'noreply@testnet.hathor.network'

    # Set the period in which the certificate is valid. In this case, the
    # reference time is now, and it will be valid between 10 minutes ago
    # and 100 years from now. This 10 minutes tolerance is to accomodate
    # differences in the time between peers.
    # To check the valid period, run a server with ssl and then run:
    # `openssl s_client -showcerts -connect localhost:8000 | openssl x509 -noout -dates`
    cert.set_serial_number(datetime.now().toordinal())
    cert.gmtime_adj_notBefore(-60 * 10)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 100)

    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    return dump_privatekey(FILETYPE_PEM, key) + dump_certificate(FILETYPE_PEM, cert)


class HathorManager(object):
    """ HathorManager manages the node, including bootstraping, peer discovery, connections,
    synchonization, and so on.
    """

    class NodeSyncState(Enum):
        SYNCING = 'SYNCING'  # This node still synchronizing with the network
        SYNCED = 'SYNCED'    # This node is up-to-date with the network

    def __init__(self, server_factory, client_factory, peer_id, network, hostname=None,
                 wallet=None, tx_storage=None, peer_storage=None, default_port=40403):
        """ peer_id: PeerId of this node.
        network: Which network will this node join? Usually either testnet or mainnet.
        hostname: The hostname of this node is used to generate its entrypoints.
        peer_storage: An instance of PeerStorage. It is instantiated by default if it is not given.
        default_port: Network default port, when only peers IP addresses are discovered.
        """
        # Factory.
        self.server_factory = server_factory
        self.server_factory.manager = self

        self.client_factory = client_factory
        self.client_factory.manager = self

        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.peer_storage = peer_storage or PeerStorage()
        self.tx_storage = tx_storage or TransactionMemoryStorage()

        # Map of peer_id to the best block height reported by that peer.
        self.peer_best_heights = defaultdict(int)

        self.wallet = wallet or Wallet()

        self.my_peer = peer_id
        self.network = network
        self.default_port = default_port

        self.blocks_per_difficulty = 5
        self.avg_time_between_blocks = 64  # in seconds
        self.min_block_weight = 10
        self.block_weight = 10  # starting difficulty (10 is too low for production)
        self.max_allowed_block_weight_change = 2

        self.node_sync_state = self.NodeSyncState.SYNCING

        # A set of blocks that we should download, according to peers.
        self.blocks_to_download = set()

        # A set of transactions that we want to download, to validate blocks we've received.
        self.txs_to_download = set()

        # Next peer to bother with download requests. TODO: Move to separate class.
        self.prev_peer_idx = 0

        # Temporary storage for transactions we're downloading while syncing. These transactions/blocks have not
        # yet been connected with the genesis DAG. Once they connect, we move them to the main tx_storage.
        self.tx_storage_sync = TransactionMemoryStorage()  # TODO: Should there be a file storage option?

        # A timer to try to reconnect to the disconnect known peers.
        self.lc_reconnect = LoopingCall(self.reconnect_to_all)

    def doStart(self):
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.connected_peers = {}
        self.start_time = time.time()
        self.lc_reconnect.start(5)

    def doStop(self):
        self.lc_reconnect.stop()

    def on_peer_connect(self, protocol):
        self.peer_storage.add_or_merge(protocol.peer)
        self.connected_peers[protocol.peer.id] = protocol

    def on_peer_disconnect(self, protocol):
        self.connected_peers.pop(protocol.peer.id)

    def propagate_tx(self, tx):
        self.tx_storage.save_transaction(tx)
        self.on_new_tx(tx)

        # Only propagate transactions once we are sufficiently syned up with the rest of the network.
        if self.node_sync_state == self.NodeSyncState.SYNCED:
            for conn in self.connected_peers.values():
                conn.send_data(tx)

    def generate_mining_block(self):
        # TODO Cache to prevent unnecessary processing.
        address = self.wallet.get_unused_address_bytes(mark_as_used=False)
        # TODO Get maximum allowed amount.
        amount = 10000
        tx_outputs = [
            TxOutput(amount, address)
        ]
        tip_blocks = self.tx_storage.get_tip_blocks()
        new_height = self.tx_storage.get_best_height() + 1
        tip_txs = self.tx_storage.get_tip_transactions(count=2)
        parents = tip_blocks + tip_txs
        return Block(weight=self.block_weight, outputs=tx_outputs, parents=parents, storage=self.tx_storage,
                     height=new_height)

    def on_new_tx(self, tx, conn=None):
        # XXX What if we receive a genesis?
        if tx.is_block:
            if tx.weight < self.block_weight:
                print('Invalid new block: weight ({}) is smaller than the minimum block weight ({})'.format(
                    tx.weight, self.block_weight)
                )
                return
            print('New block found: {}'.format(tx.hash_hex))
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

        # Save the transaction if we don't have it.
        if not self.tx_storage.transaction_exists_by_hash_bytes(tx.hash):
            # However, if the transaction doesn't connect to the genesis DAG, just save in temporary storage.
            if tx.compute_genesis_dag_connectivity(self.tx_storage, self.tx_storage_sync):
                self.tx_storage.save_transaction(tx)
            elif not self.tx_storage_sync.transaction_exists_by_hash_bytes(tx.hash):
                self.tx_storage_sync.save_transaction(tx)

        # meta = self.tx_storage.get_metadata_by_hash_bytes(tx.hash)
        # meta.peers.add(conn.peer_id.id)
        # self.tx_storage.save_metadata(meta)

        # If we're still syncing, let's check if we're ready now.
        if self.node_sync_state == self.NodeSyncState.SYNCING:
            self.try_to_synchronize()

    def on_best_height(self, best_height, conn=None):
        """A "best height" value was received from a peer."""
        self.peer_best_heights[conn.peer.id] = best_height

        # If this is greater than our best height, request more blocks and transactions.
        my_best_height = self.tx_storage.get_best_height()
        if best_height > my_best_height:

            # TODO: When does this state need to change? We can't trust this peer.
            self.node_sync_state = self.NodeSyncState.SYNCING

            # Send our latest block and request an inventory (list of hashes)
            conn.send_get_blocks()

    def on_block_hashes_received(self, block_hashes, conn=None):
        """We have received a list of hashes of blocks we need to download, according to a peer."""
        hash_set = set(x for x in block_hashes)
        self.blocks_to_download.update(hash_set)  # Performs a union and stores in blocks_to_download.
        for h in hash_set:
            print('Need to download:', h)
        self.try_to_synchronize()

    def calculate_block_difficulty(self):
        blocks = self.tx_storage.get_latest_blocks(self.blocks_per_difficulty)
        dt = blocks[0].timestamp - blocks[-1].timestamp

        if dt <= 0:
            dt = 1  # Strange situation, so, let's just increase difficulty.

        delta = (
            log(self.avg_time_between_blocks, 2)
            + log(self.blocks_per_difficulty, 2)
            - log(dt, 2)
        )

        if delta > self.max_allowed_block_weight_change:
            delta = self.max_allowed_block_weight_change
        elif delta < -self.max_allowed_block_weight_change:
            delta = -self.max_allowed_block_weight_change

        new_weight = self.block_weight + delta

        if new_weight < self.min_block_weight:
            new_weight = self.min_block_weight

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

        TODO(epnichols): Should we always conect to *all*? Should there be a max #?
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

    def connect_to(self, description, ssl=True):
        """ Attempt to connect to a peer, even if a connection already exists.
        Usually you should call `connect_to_if_not_connected`.

        If `ssl` is True, then the connection will be wraped by a TLS.
        """
        endpoint = self.clientFromString(description)

        if ssl:
            from twisted.internet import ssl
            from twisted.protocols.tls import TLSMemoryBIOFactory
            context = ssl.ClientContextFactory()
            factory = TLSMemoryBIOFactory(context, True, self.client_factory)
        else:
            factory = self.server_factory

        endpoint.connect(factory)
        print('Connecting to: {}...'.format(description))

    def serverFromString(self, description):
        """ Return an endpoint which will be used to listen to new connection.
        """
        return endpoints.serverFromString(reactor, description)

    def listen(self, description, ssl=True):
        """ Start to listen to new connection according to the description.

        If `ssl` is True, then the connection will be wraped by a TLS.

        :Example:

        `manager.listen(description='tcp:8000')`

        :param description: A description of the protocol and its parameters.
        :type description: str
        """
        endpoint = self.serverFromString(description)

        if ssl:
            # XXX Is it safe to generate a new certificate for each connection?
            #     What about CPU usage when many new connections arrive?
            from twisted.internet.ssl import PrivateCertificate
            from twisted.protocols.tls import TLSMemoryBIOFactory
            certificate = PrivateCertificate.loadPEM(generate_privkey_crt_pem())
            contextFactory = certificate.options()
            factory = TLSMemoryBIOFactory(contextFactory, False, self.server_factory)

            # from twisted.internet.ssl import CertificateOptions, TLSVersion
            # options = dict(privateKey=certificate.privateKey.original, certificate=certificate.original)
            # contextFactory = CertificateOptions(
            #     insecurelyLowerMinimumTo=TLSVersion.TLSv1_2,
            #     lowerMaximumSecurityTo=TLSVersion.TLSv1_3,
            #     **options,
            # )
        else:
            factory = self.client_factory

        endpoint.listen(factory)
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

    def schedule_transaction_download(self, hash_hex):
        """Schedule/request the download of the given transaction from peers.

        Self-throttle to avoid spamming peers. Spread requests out across known peers.  Send retries
        to different peers."""
        # TODO: Refactor this functionality into a separate PeerRequestManager class.
        # TODO: Throttle request rate.
        # TODO: Send a repeat request to a different peer each time.

        # Try to find a peer we haven't bothered recently.
        for i in range(len(self.connected_peers)):
            # Move to next peer.
            next_peer_idx = (self.prev_peer_idx + 1) % len(self.connected_peers)
            conn = list(self.connected_peers.values())[next_peer_idx]
            self.prev_peer_idx = next_peer_idx

            # Check how long it's been since we last bothered this peer.
            cur_time = time.time()
            dt_sec = cur_time - conn.last_request

            if dt_sec > 0.5:  # TODO: Pick a good time. 0.5 seconds for now.
                # Send request.
                conn.send_get_data(hash_hex)
                conn.last_request = cur_time
                break
        else:
            # Couldn't find anyone to bother. Will try again later.
            pass

    def try_to_synchronize_blocks(self):
        """Tries to perform sync to receive block data."""
        hashes_to_remove = set()
        for hash_hex in self.blocks_to_download:
            # Check if we already have this hash, either in temp or permanent storage. If so, remove from list.
            if (self.tx_storage.transaction_exists_by_hash(hash_hex) or
                    self.tx_storage_sync.transaction_exists_by_hash(hash_hex)):
                hashes_to_remove.add(hash_hex)
                continue

            # Need to download.
            self.schedule_transaction_download(hash_hex)

        # Remove blocks we already downloaded.
        self.blocks_to_download.difference_update(hashes_to_remove)

    def try_to_synchronize_transactions(self):
        """Tries to perform sync for non-block transactions.

        Move from genesis block towards the latest block, requesting all transactions required to confirm
        each block before moving on to the next block.
        """
        # TODO(epnichols): Logic for moving through blocks by height.

        # TODO(epnichols): Request transactions.
        pass

    def migrate_transactions_from_storage_sync(self):
        """Move transactions from self.storage_sync to self.storage once they are verified and connect to the
        genesis DAG."""
        # TODO(epnichols).

        pass

    def try_to_synchronize(self):
        """Checks the current blocks/transactions to determine if this nodes is sufficiently synced up with the rest
        of the network.  If not, request the missing blocks/transactions.

        Updates the NodeSyncState enum.
        """
        # print('sync attempt...')
        if self.node_sync_state == self.NodeSyncState.SYNCED:
            # Nothing to do.
            return

        self.try_to_synchronize_blocks()
        self.try_to_synchronize_transactions()
        self.migrate_transactions_from_storage_sync()

        # We're up-to-date once our set of blocks and transactions to download is empty.
        if not (self.blocks_to_download or self.txs_to_download):
            self.node_sync_state = self.NodeSyncState.SYNCED
            print('Done synchronizing!')
        else:
            # TODO(epnichols): This seems to call this function way too often...fix!
            reactor.callLater(0.5, self.try_to_synchronize)
