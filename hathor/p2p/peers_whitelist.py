from abc import ABC, abstractmethod
from typing import Any, Callable, Self
from urllib.parse import urlparse

from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from twisted.web.client import Agent

from hathor.conf import HathorSettings
from hathor.p2p.peer_id import PeerId
from hathor.p2p.utils import parse_whitelist
from hathor.reactor import ReactorProtocol as Reactor

import os

logger = get_logger()

WHITELIST_REFRESH_INTERVAL = 30
WHITELIST_RETRY_INTERVAL = 30

# The timeout in seconds for the whitelist GET request
WHITELIST_REQUEST_TIMEOUT = 45

OnRemoveCallbackType = Callable[[PeerId], None] | None


class PeersWhitelist(ABC):
    def __init__(self, reactor: Reactor) -> None:
        self.log = logger.new()
        self._reactor = reactor
        self.lc_refresh = LoopingCall(self.update)
        self.lc_refresh.clock = self._reactor
        self._current: set[PeerId] = set()
        self._on_remove_callback: OnRemoveCallbackType = None
        self._is_running: bool = False
        self._following_wl: bool = True

    def start(self, on_remove_callback: OnRemoveCallbackType) -> None:
        self._on_remove_callback = on_remove_callback
        self._start_lc()

    def _start_lc(self) -> None:
        # The deferred returned by the LoopingCall start method executes when the looping call stops running.
        # https://docs.twistedmatrix.com/en/stable/api/twisted.internet.task.LoopingCall.html
        d = self.lc_refresh.start(WHITELIST_REFRESH_INTERVAL)
        d.addErrback(self._handle_refresh_err)

    def stop(self):
        self.lc_refresh.stop()

    def _handle_refresh_err(self, *args: Any, **kwargs: Any) -> None:
        """This method will be called when an exception happens inside the whitelist update
           and ends up stopping the looping call.
           We log the error and start the looping call again.
        """
        self.log.error('whitelist refresh had an exception. Start looping call again.', args=args, kwargs=kwargs)
        self._reactor.callLater(WHITELIST_RETRY_INTERVAL, self._start_lc)

    def update(self) -> Deferred[None]:
        self._is_running = True
        try:
            d = self._unsafe_update()
        finally:
            self._is_running = False
        return d

    def follow_wl(self, follow: bool = True) -> None:
        """ Changes following_wl to True. Should not be called directly."""
        self._following_wl = follow

    def unfollow_wl(self) -> None:
        """ Changes following_wl to False. Should not be called directly."""
        self._following_wl = False
    
    def following_wl(self) -> bool:
        """ Returns True if following_wl is True, False otherwise."""
        return self._following_wl

    def current_whitelist(self) -> set[PeerId]:
        """ Returns the current whitelist as a set of PeerId."""
        return self._current

    def is_peer_whitelisted(self, peer_id: PeerId) -> bool:
        return peer_id in self._current

    def _log_diff(self, current_wl: set[PeerId], new_wl: set[PeerId]) -> None:
        peers_to_add = new_wl - current_wl
        if peers_to_add:
            self.log.info('add new peers to whitelist', peers=peers_to_add)

        peers_to_remove = current_wl - new_wl
        if peers_to_remove:
            self.log.info('remove peers from whitelist', peers=peers_to_remove)

    @abstractmethod
    def _unsafe_update(self) -> Deferred[None]:
        pass

    @classmethod
    def wl_from_cmdline(cls, reactor: Reactor, p2p_wl: str, settings: HathorSettings) -> Self | None:
        if p2p_wl.lower() in ('default', 'hathorlabs'):
            p2p_whitelist = URLPeersWhitelist(reactor, str(settings.WHITELIST_URL), True)
        elif p2p_wl.lower() in ('none', 'disabled'):
            p2p_whitelist = None
        elif os.path.isfile(p2p_wl):
            p2p_whitelist = FilePeersWhitelist(reactor, p2p_wl)
        else:
            # URLPeersWhitelist class rejects non-url paths.
            p2p_whitelist = URLPeersWhitelist(reactor, p2p_wl, True)
        return p2p_whitelist


class FilePeersWhitelist(PeersWhitelist):
    def __init__(self, reactor: Reactor, path: str) -> None:
        super().__init__(reactor)
        self._path = path

    def refresh(self) -> None:
        self._unsafe_update()

    def _unsafe_update(self) -> Deferred[None]:
        """
            Implementation of base class function.
            Reads the file in the class path.
        """
        with open(self._path, 'r', encoding='utf-8') as fp:
            content = fp.read()
        new_whitelist = parse_whitelist(content)
        self._current = new_whitelist
        
        # Log the difference between the first whitelist and the last.
        self._log_diff(self._current, new_whitelist)
        return Deferred(None)


class URLPeersWhitelist(PeersWhitelist):
    def __init__(self, reactor: Reactor, url: str | None, mainnet: bool = False) -> None:
        super().__init__(reactor)
        self._url: str | None = url
        self._http_agent = Agent(self._reactor)

        result = urlparse(self._url)
        if self._url:
            if mainnet and self._url.lower() != 'none':
                if result.scheme != 'https':
                    raise ValueError(f'invalid scheme, only https is allowed: {self._url}')

                if not result.netloc:
                    raise ValueError(f'invalid url: {self._url}')
        self.update()

    def _update_whitelist_err(self, *args: Any, **kwargs: Any) -> None:
        self.log.error('update whitelist failed', args=args, kwargs=kwargs)

    def _update_whitelist_cb(self, body: bytes) -> None:
        # assert self.manager is not None  # Assumes manager always not to be None.
        self.log.info('update whitelist got response')
        try:
            text = body.decode()
            new_whitelist = parse_whitelist(text)
        except Exception:
            self.log.exception('failed to parse whitelist')
            return

        current_whitelist = set(self._current)
        self._log_diff(current_whitelist, new_whitelist)

        peers_to_remove = current_whitelist - new_whitelist

        for peer_id in peers_to_remove:
            if self._on_remove_callback:
                self._on_remove_callback(peer_id)

        self._current = new_whitelist

    def _unsafe_update(self) -> Deferred[None]:
        """
            Implementation of the child class of PeersWhitelist, called by update()
            to fetch data from the provided url.
        """
        from twisted.web.client import readBody
        from twisted.web.http_headers import Headers
        assert self._url is not None
        self.log.info('update whitelist')
        d = self._http_agent.request(
            b'GET',
            self._url.encode(),
            Headers({'User-Agent': ['hathor-core']}),
            None)
        d.addCallback(readBody)
        d.addTimeout(WHITELIST_REQUEST_TIMEOUT, self._reactor)
        d.addCallback(self._update_whitelist_cb)
        d.addErrback(self._update_whitelist_err)
        return d
