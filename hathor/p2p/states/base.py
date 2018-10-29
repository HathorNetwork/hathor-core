# encoding: utf-8

from hathor.p2p.messages import ProtocolMessages
from twisted.logger import Logger


class BaseState(object):
    log = Logger()

    def __init__(self, protocol):
        self.protocol = protocol
        self.base_cmd_map = {
            ProtocolMessages.ERROR: self.handle_error,
            ProtocolMessages.THROTTLE: self.handle_throttle,
        }
        self.cmd_map = {}

        # This variable is set by HathorProtocol after instantiating the state
        self.state_name = None

    def handle_error(self, payload):
        self.protocol.handle_error(payload)

    def handle_throttle(self, payload):
        self.log.info('Got throttled: {}'.format(payload))

    def send_message(self, cmd, payload=None):
        self.protocol.send_message(cmd, payload)

    def send_throttle(self, key):
        max_hits, window_seconds = self.protocol.ratelimit.get_limit(key)
        payload = '{} At most {} hits every {} seconds'.format(key, max_hits, window_seconds)
        self.protocol.send_message(ProtocolMessages.THROTTLE, payload)

    def on_enter(self):
        pass

    def on_exit(self):
        pass
