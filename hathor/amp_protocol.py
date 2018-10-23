# encoding: utf-8

from twisted.internet.protocol import Factory
from twisted.protocols import amp

from hathor.transaction import Transaction, Block

import pickle
import time
from math import inf


class GetTx(amp.Command):
    arguments = [(b'hash_hex', amp.Unicode())]
    response = [(b'tx_type', amp.Unicode()),
                (b'tx_bytes', amp.String())]


class SendTx(amp.Command):
    arguments = [(b'tx_type', amp.Unicode()),
                 (b'tx_bytes', amp.String())]
    response = [(b'ret', amp.Integer())]


class TxExists(amp.Command):
    arguments = [(b'hash_hex', amp.Unicode())]
    response = [(b'ret', amp.Boolean())]


class GetTips(amp.Command):
    arguments = [(b'type', amp.Unicode()),
                 (b'timestamp', amp.Integer()),
                 (b'infinity', amp.Boolean())]
    response = [(b'tips', amp.String())]


class GetLatestTimestamp(amp.Command):
    arguments = []
    response = [(b'timestamp', amp.Integer())]


class OnNewTx(amp.Command):
    arguments = [(b'tx_type', amp.Unicode()),
                 (b'tx_bytes', amp.String())]
    response = [(b'ret', amp.Boolean())]


class GetNetworkStatus(amp.Command):
    arguments = []
    response = [(b'status', amp.String()),
                (b'id', amp.Unicode()),
                (b'entrypoints', amp.ListOf(amp.Unicode()))]


class HathorAMP(amp.AMP):
    def __init__(self, node):
        self.node = node

    def connectionMade(self):
        self.node.remoteConnection = self

    def get_tx(self, hash_hex):
        tx = self.node.tx_storage.get_transaction_by_hash(hash_hex)
        tx_type = 'block' if tx.is_block else 'tx'
        return {'tx_type': tx_type, 'tx_bytes': bytes(tx)}
    GetTx.responder(get_tx)

    def tx_exists(self, hash_hex):
        ret = self.node.tx_storage.transaction_exists_by_hash(hash_hex)
        return {'ret': ret}
    TxExists.responder(tx_exists)

    def send_tx(self, tx_type, tx_bytes):
        if tx_type == 'block':
            tx = Block.create_from_struct(tx_bytes)
        else:
            tx = Transaction.create_from_struct(tx_bytes)
        self.node.connections.send_tx_to_peers(tx)
        return {'ret': 0}
    SendTx.responder(send_tx)

    def get_tips(self, type, timestamp, infinity):
        if infinity:
            timestamp = inf
        if type == 'block':
            ret = self.node.tx_storage.get_block_tips(timestamp)
        else:
            ret = self.node.tx_storage.get_tx_tips(timestamp)
        data = pickle.dumps(ret)
        return {'tips': data}
    GetTips.responder(get_tips)

    def get_latest_timestamp(self):
        ts = self.node.tx_storage.latest_timestamp
        return {'timestamp': ts}
    GetLatestTimestamp.responder(get_latest_timestamp)

    def on_new_tx(self, tx_type, tx_bytes):
        if tx_type == 'block':
            tx = Block.create_from_struct(tx_bytes)
        else:
            tx = Transaction.create_from_struct(tx_bytes)
        tx.storage = self.node.tx_storage
        ret = self.node.on_new_tx(tx)
        return {'ret': ret}
    OnNewTx.responder(on_new_tx)

    def get_network_status(self):
        connecting_peers = []
        for endpoint, deferred in self.node.connections.connecting_peers.items():
            host = getattr(endpoint, '_host', '')
            port = getattr(endpoint, '_port', '')
            connecting_peers.append({
                'deferred': str(deferred),
                'address': '{}:{}'.format(host, port)
            })

        handshaking_peers = []
        for conn in self.node.connections.handshaking_peers:
            remote = conn.transport.getPeer()
            handshaking_peers.append({
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name,
                'uptime': time.time() - conn.connection_time,
                'app_version': conn.app_version,
            })

        connected_peers = []
        for conn in self.node.connections.connected_peers.values():
            remote = conn.transport.getPeer()
            status = {}
            for name, plugin in conn.state.plugins.items():
                status[name] = plugin.get_status()
            connected_peers.append({
                'id': conn.peer.id,
                'app_version': conn.app_version,
                'uptime': time.time() - conn.connection_time,
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name,
                # 'received_bytes': conn.received_bytes,
                'last_message': time.time() - conn.last_message,
                'plugins': status,
            })

        known_peers = []
        for peer in self.node.connections.peer_storage.values():
            known_peers.append({
                'id': peer.id,
                'entrypoints': peer.entrypoints,
            })

        status = {}
        status['connecting_peers'] = connecting_peers
        status['handshaking_peers'] = handshaking_peers
        status['connected_peers'] = connected_peers
        status['known_peers'] = known_peers
        return {'status': pickle.dumps(status),
                'id': self.node.connections.my_peer.id,
                'entrypoints': self.node.connections.my_peer.entrypoints}
    GetNetworkStatus.responder(get_network_status)


class HathorAMPFactory(Factory):
    def __init__(self, node):
        """
        :type node: HathorManager or NetworkManager
        """
        super().__init__()
        self.node = node

    def buildProtocol(self, addr):
        return HathorAMP(self.node)
