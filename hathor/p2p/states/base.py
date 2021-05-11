from typing import TYPE_CHECKING, Callable, Dict, Optional

from structlog import get_logger

from hathor.p2p.messages import ProtocolMessages

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

logger = get_logger()


class BaseState:
    protocol: 'HathorProtocol'
    cmd_map: Dict[ProtocolMessages, Callable[[str], None]]

    def __init__(self, protocol: 'HathorProtocol'):
        self.log = logger.new(**protocol.get_logger_context())
        self.protocol = protocol
        self.cmd_map = {
            ProtocolMessages.ERROR: self.handle_error,
            ProtocolMessages.THROTTLE: self.handle_throttle,
        }

        # This variable is set by HathorProtocol after instantiating the state
        self.state_name = None

    def handle_error(self, payload: str) -> None:
        self.protocol.handle_error(payload)

    def handle_throttle(self, payload: str) -> None:
        self.log.info('throttled', payload=payload)

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        self.protocol.send_message(cmd, payload)

    def send_throttle(self, key: str) -> None:
        limit = self.protocol.ratelimit.get_limit(key)
        if limit is None:
            return
        max_hits, window_seconds = limit
        payload = '{} At most {} hits every {} seconds'.format(key, max_hits, window_seconds)
        self.protocol.send_message(ProtocolMessages.THROTTLE, payload)

    def on_enter(self) -> None:
        raise NotImplementedError

    def on_exit(self) -> None:
        pass
