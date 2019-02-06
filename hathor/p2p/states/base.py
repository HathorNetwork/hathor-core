from typing import TYPE_CHECKING, Callable, Dict, Optional

from twisted.logger import Logger

from hathor.p2p.messages import ProtocolMessages

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401


class BaseState:
    log = Logger()

    protocol: 'HathorProtocol'
    base_cmd_map: Dict[ProtocolMessages, Callable[[str], None]]
    cmd_map: Dict[ProtocolMessages, Callable[[str], None]]

    def __init__(self, protocol: 'HathorProtocol'):
        self.protocol = protocol
        self.base_cmd_map = {
            ProtocolMessages.ERROR: self.handle_error,
            ProtocolMessages.THROTTLE: self.handle_throttle,
        }
        self.cmd_map = {}

        # This variable is set by HathorProtocol after instantiating the state
        self.state_name = None

    def handle_error(self, payload: str) -> None:
        self.protocol.handle_error(payload)

    def handle_throttle(self, payload: str):
        self.log.info('Got throttled: {payload}', payload=payload)

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        self.protocol.send_message(cmd, payload)

    def send_throttle(self, key):
        max_hits, window_seconds = self.protocol.ratelimit.get_limit(key)
        payload = '{} At most {} hits every {} seconds'.format(key, max_hits, window_seconds)
        self.protocol.send_message(ProtocolMessages.THROTTLE, payload)

    def on_enter(self):
        raise NotImplementedError

    def on_exit(self) -> None:
        pass
