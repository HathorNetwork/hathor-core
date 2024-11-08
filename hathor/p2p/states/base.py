# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from collections.abc import Coroutine
from typing import TYPE_CHECKING, Any, Callable, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred

from hathor.conf.settings import HathorSettings
from hathor.p2p import P2PDependencies
from hathor.p2p.messages import ProtocolMessages

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

logger = get_logger()


class BaseState:
    name: str
    cmd_map: dict[
        ProtocolMessages,
        Callable[[str], None] | Callable[[str], Deferred[None]] | Callable[[str], Coroutine[Deferred[None], Any, None]]
    ]

    def __init__(self, dependencies: P2PDependencies, protocol: HathorProtocol | None = None):
        self.log = logger.new(**protocol.get_logger_context()) if protocol else logger.new()
        self.dependencies = dependencies
        self._settings: HathorSettings = dependencies.settings
        self._protocol = protocol
        self.cmd_map = {
            ProtocolMessages.ERROR: self.handle_error,
            ProtocolMessages.THROTTLE: self.handle_throttle,
        }

    @property
    def protocol(self) -> HathorProtocol:
        assert self._protocol is not None
        return self._protocol

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
        pass

    def on_exit(self) -> None:
        pass

    def prepare_to_disconnect(self) -> None:
        """Called when we will disconnect with the peer."""
        pass

    @staticmethod
    def next_state_type() -> type[BaseState] | None:
        return None
