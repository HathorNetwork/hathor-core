# encoding: utf-8

from twisted.internet.protocol import Factory
from twisted.protocols import amp

from hathor.transaction import Transaction, Block

import pickle
import time
from math import inf


# This file contains the various AMP calls that can be made between the two processes.

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


class PublishEvent(amp.Command):
    arguments = [(b'event_type', amp.Unicode()),
                 (b'event_data', amp.String())]
    response = [(b'ret', amp.Boolean())]


class HathorAMP(amp.AMP):
    def __init__(self, manager):
        """
        :param manager: the class responsible for handling inter-process communication
        :type manager: HathorManager or NetworkManager
        """
        self.manager = manager

    def connectionMade(self):
        self.manager.remote_connection = self

    def get_tx(self, hash_hex):
        tx = self.manager.tx_storage.get_transaction_by_hash(hash_hex)
        tx_type = 'block' if tx.is_block else 'tx'
        return {'tx_type': tx_type, 'tx_bytes': bytes(tx)}
    GetTx.responder(get_tx)

    def tx_exists(self, hash_hex):
        ret = self.manager.tx_storage.transaction_exists_by_hash(hash_hex)
        return {'ret': ret}
    TxExists.responder(tx_exists)

    def send_tx(self, tx_type, tx_bytes):
        if tx_type == 'block':
            tx = Block.create_from_struct(tx_bytes)
        else:
            tx = Transaction.create_from_struct(tx_bytes)
        self.manager.connections.send_tx_to_peers(tx)
        return {'ret': 0}
    SendTx.responder(send_tx)

    def get_tips(self, type, timestamp, infinity):
        if infinity:
            timestamp = inf
        if type == 'block':
            ret = self.manager.tx_storage.get_block_tips(timestamp)
        else:
            ret = self.manager.tx_storage.get_tx_tips(timestamp)
        data = pickle.dumps(ret)
        return {'tips': data}
    GetTips.responder(get_tips)

    def get_latest_timestamp(self):
        ts = self.manager.tx_storage.latest_timestamp
        return {'timestamp': ts}
    GetLatestTimestamp.responder(get_latest_timestamp)

    def on_new_tx(self, tx_type, tx_bytes):
        if tx_type == 'block':
            tx = Block.create_from_struct(tx_bytes)
        else:
            tx = Transaction.create_from_struct(tx_bytes)
        tx.storage = self.manager.tx_storage
        ret = self.manager.on_new_tx(tx)
        return {'ret': ret}
    OnNewTx.responder(on_new_tx)

    def get_network_status(self):
        connecting_peers = []
        for endpoint, deferred in self.manager.connections.connecting_peers.items():
            host = getattr(endpoint, '_host', '')
            port = getattr(endpoint, '_port', '')
            connecting_peers.append({
                'deferred': str(deferred),
                'address': '{}:{}'.format(host, port)
            })

        handshaking_peers = []
        for conn in self.manager.connections.handshaking_peers:
            remote = conn.transport.getPeer()
            handshaking_peers.append({
                'address': '{}:{}'.format(remote.host, remote.port),
                'state': conn.state.state_name,
                'uptime': time.time() - conn.connection_time,
                'app_version': conn.app_version,
            })

        connected_peers = []
        for conn in self.manager.connections.connected_peers.values():
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
        for peer in self.manager.connections.peer_storage.values():
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
                'id': self.manager.connections.my_peer.id,
                'entrypoints': self.manager.connections.my_peer.entrypoints}
    GetNetworkStatus.responder(get_network_status)

    def publish_event(self, event_type, event_data):
        self.manager.pubsub.publish_from_process(event_type, event_data)
        return {'ret': True}
    PublishEvent.responder(publish_event)


class HathorAMPFactory(Factory):
    def __init__(self, manager):
        """
        :param manager: the class responsible for handling inter-process communication
        :type manager: HathorManager or NetworkManager
        """
        super().__init__()
        self.manager = manager

    def buildProtocol(self, addr):
        return HathorAMP(self.manager)
