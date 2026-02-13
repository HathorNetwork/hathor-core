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

from abc import ABC, abstractmethod
from typing import Any, Callable

from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall

from hathor.p2p.peer_id import PeerId
from hathor.p2p.whitelist.parsing import WhitelistPolicy
from hathor.reactor import ReactorProtocol as Reactor

logger = get_logger()

WHITELIST_REFRESH_INTERVAL = 30

# Exponential backoff constants for retry intervals
WHITELIST_RETRY_INTERVAL_MIN = 30
WHITELIST_RETRY_INTERVAL_MAX = 300

OnRemoveCallbackType = Callable[[PeerId], None] | None


class PeersWhitelist(ABC):
    def __init__(self, reactor: Reactor) -> None:
        self.log = logger.new()
        self._reactor = reactor
        self.lc_refresh = LoopingCall(self.update)
        self.lc_refresh.clock = self._reactor
        self._current: set[PeerId] = set()
        self._policy: WhitelistPolicy = WhitelistPolicy.ONLY_WHITELISTED_PEERS
        self._on_remove_callback: OnRemoveCallbackType = None
        self._is_running: bool = False
        self._consecutive_failures: int = 0
        self._has_successful_fetch: bool = False
        self._bootstrap_peers: set[PeerId] = set()

    def add_bootstrap_peer(self, peer_id: PeerId) -> None:
        """Add a bootstrap peer ID. These are allowed during grace period."""
        self._bootstrap_peers.add(peer_id)
        self.log.debug('Bootstrap peer added', peer_id=peer_id)

    def start(self, on_remove_callback: OnRemoveCallbackType) -> None:
        self._on_remove_callback = on_remove_callback
        self._start_lc()

    def _start_lc(self) -> None:
        # The deferred returned by the LoopingCall start method executes when the looping call stops running.
        # https://docs.twistedmatrix.com/en/stable/api/twisted.internet.task.LoopingCall.html
        d = self.lc_refresh.start(WHITELIST_REFRESH_INTERVAL)
        d.addErrback(self._handle_refresh_err)

    def stop(self) -> None:
        if self.lc_refresh.running:
            self.lc_refresh.stop()

    def _get_retry_interval(self) -> int:
        """Calculate retry interval with exponential backoff.

        Returns interval in seconds: 30 → 60 → 120 → max 300.
        """
        interval = WHITELIST_RETRY_INTERVAL_MIN * (2 ** self._consecutive_failures)
        return min(interval, WHITELIST_RETRY_INTERVAL_MAX)

    def _on_update_success(self) -> None:
        """Called when whitelist update succeeds. Resets backoff counter."""
        self._consecutive_failures = 0

    def _on_update_failure(self) -> None:
        """Called when whitelist update fails. Increments backoff counter."""
        self._consecutive_failures += 1

    def _handle_refresh_err(self, *args: Any, **kwargs: Any) -> None:
        """This method will be called when an exception happens inside the whitelist update
           and ends up stopping the looping call.
           We log the error and start the looping call again with exponential backoff.
        """
        self._on_update_failure()
        retry_interval = self._get_retry_interval()
        self.log.error(
            'whitelist refresh had an exception. Start looping call again.',
            args=args,
            kwargs=kwargs,
            retry_interval=retry_interval,
            consecutive_failures=self._consecutive_failures
        )
        self._reactor.callLater(retry_interval, self._start_lc)

    def update(self) -> Deferred[None]:
        # Avoiding re-entrancy. If running, should not update once more.
        if self._is_running:
            self.log.warning('whitelist update already running, skipping execution.')
            d: Deferred[None] = Deferred()
            d.callback(None)
            return d

        self._is_running = True
        d = self._unsafe_update()
        d.addBoth(lambda _: setattr(self, '_is_running', False))
        return d

    def add_peer(self, peer_id: PeerId) -> None:
        """ Adds a peer to the current whitelist. """
        if peer_id not in self._current:
            self._current.add(peer_id)
            self.log.info('Peer added to whitelist', peer_id=peer_id)

    def current_whitelist(self) -> set[PeerId]:
        """ Returns the current whitelist as a set of PeerId."""
        return self._current

    def policy(self) -> WhitelistPolicy:
        """ Returns the current whitelist policy."""
        return self._policy

    def is_peer_whitelisted(self, peer_id: PeerId) -> bool:
        """ Returns True if peer is whitelisted or policy is ALLOW_ALL.

        During the grace period (before first successful fetch), only bootstrap peers
        are allowed to prevent connecting to arbitrary peers before the whitelist is loaded.
        """
        # Grace period: only allow bootstrap peers until first successful fetch
        if not self._has_successful_fetch:
            return peer_id in self._bootstrap_peers
        if self._policy == WhitelistPolicy.ALLOW_ALL:
            return True
        return peer_id in self._current

    def _log_diff(self, current_whitelist: set[PeerId], new_whitelist: set[PeerId]) -> None:
        peers_to_add = new_whitelist - current_whitelist
        if peers_to_add:
            self.log.info('add new peers to whitelist', peers=peers_to_add)

        peers_to_remove = current_whitelist - new_whitelist
        if peers_to_remove:
            self.log.info('remove peers from whitelist', peers=peers_to_remove)

    def _apply_whitelist_update(self, new_whitelist: set[PeerId], new_policy: WhitelistPolicy) -> None:
        """Apply a whitelist update: log diff, call remove callbacks, and update state.

        This is the common logic used by both URL and file-based whitelists after
        successfully parsing new whitelist content.
        """
        current_whitelist = set(self._current)
        self._log_diff(current_whitelist, new_whitelist)

        peers_to_remove = current_whitelist - new_whitelist
        for peer_id in peers_to_remove:
            if self._on_remove_callback:
                self._on_remove_callback(peer_id)

        self._current = new_whitelist
        self._policy = new_policy
        self._has_successful_fetch = True
        self._on_update_success()

    @abstractmethod
    def source(self) -> str | None:
        """Return the source of the whitelist (URL or file path)."""
        raise NotImplementedError

    @abstractmethod
    def _unsafe_update(self) -> Deferred[None]:
        raise NotImplementedError
