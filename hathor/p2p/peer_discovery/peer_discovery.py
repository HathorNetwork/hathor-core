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

from abc import ABC, abstractmethod
from typing import Callable


class PeerDiscovery(ABC):
    """ Base class to implement peer discovery strategies.
    """

    @abstractmethod
    async def discover_and_connect(self, connect_to_endpoint: Callable[..., None]) -> None:
        """ This method must discover the peers and call `connect_to_endpoint` for each of them.

        :param connect_to_endpoint: Function which will be called for each discovered peer.
        :type connect_to_endpoint: function
        """
        raise NotImplementedError
