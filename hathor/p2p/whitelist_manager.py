# Copyright 2026 Hathor Labs
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

from typing import Any, Callable, Optional

from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from twisted.web.client import Agent

from hathor.conf.settings import HathorSettings
from hathor.p2p.peer_id import PeerId
from hathor.p2p.utils import WhitelistPolicy, parse_whitelist
from hathor.reactor import ReactorProtocol as Reactor

logger = get_logger()

# The timeout in seconds for the whitelist GET request
WHITELIST_REQUEST_TIMEOUT = 45


class WhitelistManager:
    """Owns the peer whitelist: enabled flag, active policy, peer list, and
    the periodic refresh loop. Centralizes the connection-admission decision
    so that other modules only consult `is_connection_allowed`.
    """

    def __init__(
        self,
        *,
        settings: HathorSettings,
        reactor: Reactor,
        drop_connection: Callable[[PeerId], None],
    ) -> None:
        self.log = logger.new()
        self._settings = settings
        self._reactor = reactor
        self._drop_connection = drop_connection

        # When True, the protocol-level whitelist mechanism is active and the manager
        # periodically fetches and applies updates from WHITELIST_URL.
        self.enabled = settings.ENABLE_PEER_WHITELIST

        self.policy: WhitelistPolicy = WhitelistPolicy.ONLY_WHITELISTED_PEERS
        self.peers: set[PeerId] = set()

        self._http_agent: Optional[Agent] = None
        self._loop: Optional[LoopingCall] = None
        if self.enabled:
            self._loop = LoopingCall(self.update)
            self._loop.clock = reactor

    def start(self) -> None:
        """Start the periodic refresh loop. No-op when the whitelist is disabled."""
        if not self.enabled:
            return
        self._http_agent = Agent(self._reactor)
        self._start_loop()

    def _start_loop(self) -> None:
        assert self._loop is not None
        d = self._loop.start(30)
        d.addErrback(self._handle_loop_err)

    def _handle_loop_err(self, *args: Any, **kwargs: Any) -> None:
        """Called when the LoopingCall stops due to an exception. Restart it."""
        self.log.error('whitelist reconnect had an exception. Start looping call again.',
                       args=args, kwargs=kwargs)
        self._reactor.callLater(30, self._start_loop)

    def add_peer(self, peer_id: PeerId) -> None:
        assert self.enabled
        if peer_id in self.peers:
            self.log.info('peer already in whitelist', peer_id=peer_id)
            return
        self.peers.add(peer_id)

    def remove_peer_and_disconnect(self, peer_id: PeerId) -> None:
        assert self.enabled
        if peer_id not in self.peers:
            return
        self.peers.remove(peer_id)
        self._drop_connection(peer_id)

    def is_connection_allowed(self, peer_id: PeerId) -> bool:
        """Return True if the peer is allowed to connect under the current policy."""
        if peer_id in self.peers:
            return True
        if self.policy == WhitelistPolicy.ALLOW_ALL:
            return True
        if self.enabled:
            return False
        return True

    def update(self) -> Deferred[None]:
        from twisted.web.client import readBody
        from twisted.web.http_headers import Headers
        assert self._settings.WHITELIST_URL is not None
        assert self._http_agent is not None
        self.log.info('update whitelist')
        d = self._http_agent.request(
            b'GET',
            self._settings.WHITELIST_URL.encode(),
            Headers({'User-Agent': ['hathor-core']}),
            None)
        d.addCallback(readBody)
        d.addTimeout(WHITELIST_REQUEST_TIMEOUT, self._reactor)
        d.addCallback(self._update_cb)
        d.addErrback(self._update_err)
        return d

    def _update_err(self, *args: Any, **kwargs: Any) -> None:
        self.log.error('update whitelist failed', args=args, kwargs=kwargs)

    def _update_cb(self, body: bytes) -> None:
        self.log.info('update whitelist got response')
        try:
            new_whitelist, new_policy = parse_whitelist(body.decode())
        except Exception:
            self.log.exception('failed to parse whitelist')
            return
        if new_policy != self.policy:
            self.log.info('whitelist policy changed', old=self.policy, new=new_policy)
            self.policy = new_policy
        to_add = new_whitelist - self.peers
        to_remove = self.peers - new_whitelist
        if to_add:
            self.log.info('add new peers to whitelist', peers=to_add)
        if to_remove:
            self.log.info('remove peers from whitelist', peers=to_remove)
        for peer_id in to_add:
            self.add_peer(peer_id)
        for peer_id in to_remove:
            self.remove_peer_and_disconnect(peer_id)
