# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List

from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall

from hathor.p2p.netfilter.matches import NetfilterMatch, NetfilterMatchIPAddress
from hathor.util import Reactor

if TYPE_CHECKING:
    from hathor.p2p.netfilter.context import NetfilterContext

logger = get_logger()


class NetfilterMatchRemoteURL(NetfilterMatch):
    """Base class to match items in a list updated from a remote URL."""
    header: str

    def __init__(self, name: str, reactor: Reactor, url: str, update_interval: int = 30) -> None:
        self.log = logger.new()
        self.name = name
        self.reactor = reactor
        self.url = url
        self.update_interval = update_interval
        self.lc_update = LoopingCall(self.update)
        self.items: List[str] = []
        self.matches: List[NetfilterMatch] = []
        self.method = 'GET'
        self.headers = {
            'User-Agent': ['hathor-core'],
        }

    def to_json(self) -> Dict[str, Any]:
        data = super().to_json()
        data['match_params']['name'] = self.name
        data['match_params']['url'] = self.url
        data['match_params']['update_interval'] = self.update_interval
        data['match_params']['method'] = self.method
        data['match_params']['headers'] = self.headers
        data['match_params']['items'] = self.items
        data['match_params']['matches'] = [match.to_json() for match in self.matches]
        return data

    def start(self) -> None:
        self.lc_update.start(self.update_interval)

    def stop(self) -> None:
        self.lc_update.stop()

    def update(self) -> Deferred:
        """Update the list of items."""
        from twisted.web.client import Agent, readBody
        from twisted.web.http_headers import Headers
        agent = Agent(self.reactor)
        d = agent.request(
            self.method.encode(),
            self.url.encode(),
            Headers(self.headers),
            None
        )
        d.addCallback(readBody)
        d.addErrback(self._update_err)
        d.addCallback(self._update_cb)
        return d

    def match(self, context: 'NetfilterContext') -> bool:
        for match in self.matches:
            if match.match(context):
                return True
        return False

    def _update_err(self, *args: Any, **kwargs: Any) -> None:
        """Called when the HTTP Request fails."""
        self.log.debug('update failed', args=args, kwargs=kwargs)

    def _update_cb(self, body: bytes) -> None:
        """Called when it gets an HTTP Response."""
        from hathor.p2p.utils import parse_file
        self.log.debug('update got response')
        try:
            text = body.decode()
            new_items = parse_file(text, header=self.header)
        except Exception:
            self.log.exception('failed to parse list')
            return
        self.items = new_items
        self.matches = [self.generate_match(x) for x in self.items]

    @abstractmethod
    def generate_match(self, item: str) -> NetfilterMatch:
        """Generate a match object for `item`."""
        raise NotImplementedError


class NetfilterMatchIPAddressRemoteURL(NetfilterMatchRemoteURL):
    """Match IP addresses against a list."""
    header = 'hathor-ip-list'

    def generate_match(self, item: str) -> NetfilterMatch:
        return NetfilterMatchIPAddress(item)
