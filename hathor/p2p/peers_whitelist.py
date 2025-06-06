from abc import ABC, abstractmethod
from typing import Any, Callable
from urllib.parse import urlparse

from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall

from hathor.p2p.peer_id import PeerId
from hathor.p2p.utils import parse_whitelist
from hathor.reactor import ReactorProtocol as Reactor

logger = get_logger()

WHITELIST_REFRESH_INTERVAL = 30
WHITELIST_RETRY_INTERVAL = 30

# The timeout in seconds for the whitelist GET request
WHITELIST_REQUEST_TIMEOUT = 45

OnRemoveCallbackType = Callable[[PeerId], None]


class PeersWhitelist(ABC):
    def __init__(self, reactor: Reactor) -> None:
        self.log = logger.new()
        self._reactor = reactor
        self.lc_refresh = LoopingCall(self.update)
        self.lc_refresh.clock = self._reactor
        self._current: list[PeerId] = []
        self._on_remove_callback: OnRemoveCallbackType | None = None
        self._is_running: bool = False

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
        self.reactor.callLater(WHITELIST_RETRY_INTERVAL, self._start_lc)

    def update(self) -> None:
        self._is_running = True
        try:
            self._unsafe_update()
        finally:
            self._is_running = False

    @abstractmethod
    def _unsafe_update(self) -> Deferred[None]:
        pass

    @abstractmethod
    def is_peer_whitelisted(self) -> None:
        raise NotImplementedError


class FilePeersWhitelist(PeersWhitelist):
    def __init__(self, reactor: Reactor, path: str) -> None:
        self._path = path

    def refresh(self) -> None:
        with open(self._path, 'r', encoding='utf-8') as fp:
            content = fp.read()
        new_whitelist = parse_whitelist(content)
        self._current = new_whitelist


class URLPeersWhitelist(PeersWhitelist):
    def __init__(self, reactor: Reactor, url: str) -> None:
        super().__init__(reactor)
        self._url: str = url

        result = urlparse(self._url)
        if result.scheme != 'https':
            raise ValueError(f'invalid scheme, only https is allowed: {self._url}')

        if not result.netloc:
            raise ValueError(f'invalid url: {self._url}')

    def update(self) -> Deferred[None]:
        from twisted.web.client import readBody
        from twisted.web.http_headers import Headers
        assert self._settings.WHITELIST_URL is not None
        self.log.info('update whitelist')
        d = self._http_agent.request(
            b'GET',
            self._settings.WHITELIST_URL.encode(),
            Headers({'User-Agent': ['hathor-core']}),
            None)
        d.addCallback(readBody)
        d.addTimeout(WHITELIST_REQUEST_TIMEOUT, self.reactor)
        d.addCallback(self._update_whitelist_cb)
        d.addErrback(self._update_whitelist_err)
        return d

    def _update_whitelist_err(self, *args: Any, **kwargs: Any) -> None:
        self.log.error('update whitelist failed', args=args, kwargs=kwargs)

    def _update_whitelist_cb(self, body: bytes) -> None:
        assert self.manager is not None
        self.log.info('update whitelist got response')
        try:
            text = body.decode()
            new_whitelist = parse_whitelist(text)
        except Exception:
            self.log.exception('failed to parse whitelist')
            return

        current_whitelist = set(self._current)

        peers_to_add = new_whitelist - current_whitelist
        if peers_to_add:
            self.log.info('add new peers to whitelist', peers=peers_to_add)

        peers_to_remove = current_whitelist - new_whitelist
        if peers_to_remove:
            self.log.info('remove peers peers from whitelist', peers=peers_to_remove)

        for peer_id in peers_to_remove:
            self.on_remove_callback(peer_id)

        self._current = new_whitelist
