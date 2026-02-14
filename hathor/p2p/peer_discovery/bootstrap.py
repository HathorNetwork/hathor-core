# Copyright 2024 Hathor Labs
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

from typing import Callable

from structlog import get_logger
from typing_extensions import override

from hathor.p2p.peer_endpoint import PeerEndpoint

from .peer_discovery import PeerDiscovery

logger = get_logger()


class BootstrapPeerDiscovery(PeerDiscovery):
    """ It implements a bootstrap peer discovery, which receives a static list of peers.
    """

    def __init__(self, entrypoints: list[PeerEndpoint]):
        """
        :param entrypoints: Addresses of peers to connect to.
        """
        super().__init__()
        self.log = logger.new()
        self.entrypoints = entrypoints

    @override
    async def discover_and_connect(self, connect_to_endpoint: Callable[[PeerEndpoint], None]) -> None:
        for entrypoint in self.entrypoints:
            connect_to_endpoint(entrypoint, discovery_call=True)  # type: ignore[call-arg]
