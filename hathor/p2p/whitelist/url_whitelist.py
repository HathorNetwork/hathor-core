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

from typing import Any
from urllib.parse import urlparse

from twisted.internet.defer import Deferred
from twisted.web.client import Agent

from hathor.p2p.whitelist.parsing import parse_whitelist_with_policy
from hathor.p2p.whitelist.peers_whitelist import PeersWhitelist
from hathor.reactor import ReactorProtocol as Reactor

# The timeout in seconds for the whitelist GET request
WHITELIST_REQUEST_TIMEOUT = 45


class URLPeersWhitelist(PeersWhitelist):
    def __init__(self, reactor: Reactor, url: str | None, mainnet: bool = False) -> None:
        super().__init__(reactor)
        self._url: str | None = url
        self._http_agent = Agent(self._reactor)

        if self._url is None:
            return
        if self._url.lower().strip() == 'none':
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

    def _update_whitelist_cb(self, body: bytes) -> None:
        self.log.info('update whitelist got response')
        try:
            text = body.decode('utf-8')
        except UnicodeDecodeError as e:
            self.log.error('Failed to decode whitelist response', url=self._url, error=str(e))
            self._on_update_failure()
            return

        try:
            new_whitelist, new_policy = parse_whitelist_with_policy(text)
        except ValueError as e:
            self.log.error('Failed to parse whitelist content', url=self._url, error=str(e))
            self._on_update_failure()
            return
        except Exception:
            self.log.exception('Unexpected error parsing whitelist', url=self._url)
            self._on_update_failure()
            return

        self._apply_whitelist_update(new_whitelist, new_policy)

    def _unsafe_update(self) -> Deferred[None]:
        """
            Implementation of the child class of PeersWhitelist, called by update()
            to fetch data from the provided url.
        """
        from twisted.web.client import readBody
        from twisted.web.http_headers import Headers

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
        d.addCallback(readBody)  # type: ignore[call-overload]
        d.addTimeout(WHITELIST_REQUEST_TIMEOUT, self._reactor)
        d.addCallback(self._update_whitelist_cb)  # type: ignore[call-overload]
        d.addErrback(self._update_whitelist_err)
        return d
