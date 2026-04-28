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

from typing import Any
from urllib.parse import urlparse

from twisted.internet import threads
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.web.iweb import IResponse

from hathor.p2p.whitelist.parsing import parse_whitelist_with_policy
from hathor.p2p.whitelist.peers_whitelist import PeersWhitelist
from hathor.reactor import ReactorProtocol as Reactor

# The timeout in seconds for the whitelist GET request
WHITELIST_REQUEST_TIMEOUT = 45

# Maximum body size accepted from a whitelist URL. 16 MiB holds ~256k 64-hex
# peer IDs with newlines; anything larger is almost certainly a misconfigured
# or malicious endpoint attempting to OOM the node.
WHITELIST_MAX_BODY_BYTES = 16 * 1024 * 1024


class _BoundedBodyProtocol(Protocol):
    """Collects response body bytes up to a cap; aborts the transport on overflow."""

    def __init__(self, finished: Deferred, max_bytes: int) -> None:
        self._finished = finished
        self._max_bytes = max_bytes
        self._buffer: list[bytes] = []
        self._size = 0
        self._aborted = False

    def dataReceived(self, data: bytes) -> None:
        if self._aborted:
            return
        self._size += len(data)
        if self._size > self._max_bytes:
            self._aborted = True
            self.transport.stopProducing()
            self._finished.errback(ValueError(
                f'whitelist body exceeded {self._max_bytes} bytes cap'
            ))
            return
        self._buffer.append(data)

    def connectionLost(self, reason: Any) -> None:
        if self._aborted:
            return
        from twisted.web.client import ResponseDone
        from twisted.web.http import PotentialDataLoss
        if reason.check(ResponseDone, PotentialDataLoss):
            self._finished.callback(b''.join(self._buffer))
        else:
            self._finished.errback(reason)


def _read_bounded_body(response: IResponse, max_bytes: int) -> Deferred[bytes]:
    """Drop-in replacement for readBody that enforces a size cap."""
    finished: Deferred[bytes] = Deferred()
    response.deliverBody(_BoundedBodyProtocol(finished, max_bytes))
    return finished


class URLPeersWhitelist(PeersWhitelist):
    def __init__(self, reactor: Reactor, url: str | None, mainnet: bool = False) -> None:
        super().__init__(reactor)
        self._url: str | None = url
        self._http_agent = Agent(self._reactor)

        if self._url is None:
            return
        if self._url.lower() == 'none':
            self._url = None
            return

        result = urlparse(self._url)
        if mainnet:
            if result.scheme != 'https':
                raise ValueError(f'invalid scheme: {self._url}')

            if not result.netloc:
                raise ValueError(f'invalid url: {self._url}')

    def url(self) -> str | None:
        return self._url

    def source(self) -> str | None:
        """Return the URL as the whitelist source."""
        return self._url

    def _update_whitelist_err(self, failure: Any) -> None:
        from twisted.internet.defer import TimeoutError
        self._on_update_failure()
        error = failure.value
        if isinstance(error, TimeoutError):
            self.log.warning(
                'Whitelist URL request timed out',
                url=self._url,
                timeout=WHITELIST_REQUEST_TIMEOUT,
                consecutive_failures=self._consecutive_failures
            )
        else:
            self.log.error(
                'Failed to fetch whitelist from URL',
                url=self._url,
                error_type=type(error).__name__,
                error=str(error),
                consecutive_failures=self._consecutive_failures
            )

    def _update_whitelist_cb(self, body: bytes) -> Deferred[None]:
        """Decode and parse the body off the reactor thread, then apply on it.

        The re-entrancy guard in PeersWhitelist.update() already serializes
        calls, so at most one parse is in flight per whitelist instance.
        """
        self.log.info('update whitelist got response')
        d: Deferred[tuple] = threads.deferToThread(self._decode_and_parse, body)
        d.addCallback(self._apply_parsed_whitelist)
        d.addErrback(self._handle_parse_err)
        return d  # type: ignore[return-value]

    def _decode_and_parse(self, body: bytes) -> tuple:
        """Runs in a worker thread. Decode UTF-8 and parse the whitelist body."""
        text = body.decode('utf-8')
        return parse_whitelist_with_policy(text)

    def _apply_parsed_whitelist(self, parsed: tuple) -> None:
        new_whitelist, new_policy = parsed
        self._apply_whitelist_update(new_whitelist, new_policy)

    def _handle_parse_err(self, failure: Any) -> None:
        self._on_update_failure()
        error = failure.value
        if isinstance(error, UnicodeDecodeError):
            self.log.error('Failed to decode whitelist response', url=self._url, error=str(error))
        elif isinstance(error, ValueError):
            self.log.error('Failed to parse whitelist content', url=self._url, error=str(error))
        else:
            self.log.error(
                'Unexpected error parsing whitelist',
                url=self._url,
                error_type=type(error).__name__,
                error=str(error),
            )

    def _unsafe_update(self) -> Deferred[None]:
        """
            Implementation of the child class of PeersWhitelist, called by update()
            to fetch data from the provided url.
        """
        # Guard against URL being None (e.g., when set to "none" string)
        if self._url is None:
            self.log.debug('skipping whitelist update, url is None')
            d: Deferred[None] = Deferred()
            d.callback(None)
            return d

        self.log.info('update whitelist')
        d = self._http_agent.request(
            b'GET',
            self._url.encode(),
            Headers({'User-Agent': ['hathor-core']}),
            None)
        d.addCallback(self._check_response_status)  # type: ignore[call-overload]
        d.addCallback(_read_bounded_body, WHITELIST_MAX_BODY_BYTES)  # type: ignore[call-overload]
        d.addTimeout(WHITELIST_REQUEST_TIMEOUT, self._reactor)
        d.addCallback(self._update_whitelist_cb)  # type: ignore[call-overload]
        d.addErrback(self._update_whitelist_err)
        return d

    def _check_response_status(self, response: IResponse) -> IResponse:
        """Check HTTP response status code before reading body."""
        if response.code < 200 or response.code >= 300:
            raise ValueError(f'Whitelist URL returned HTTP {response.code}')
        return response
