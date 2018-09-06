# encoding: utf-8

from enum import Enum


class BaseState(object):
    class ProtocolCommand(Enum):
        # ---
        # General Error Messages
        # ---
        # Notifies an error.
        ERROR = 'ERROR'

        # Notifies a throttle.
        THROTTLE = 'THROTTLE'

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

    def __init__(self, protocol):
        self.protocol = protocol
        self.base_cmd_map = {
            self.ProtocolCommand.ERROR: self.handle_error,
            self.ProtocolCommand.THROTTLE: self.handle_throttle,
        }
        self.cmd_map = {}

    def handle_error(self, payload):
        self.protocol.handle_error(payload)

    def handle_throttle(self, payload):
        print('Got throttled!', payload)

    def send_message(self, cmd, payload=None):
        self.protocol.send_message(cmd, payload)

    def send_throttle(self, key):
        max_hits, window_seconds = self.protocol.ratelimit.get_limit(key)
        payload = '{} At most {} hits every {} seconds'.format(key, max_hits, window_seconds)
        self.protocol.send_message(self.ProtocolCommand.THROTTLE, payload)

    def on_enter(self):
        pass

    def on_exit(self):
        pass
