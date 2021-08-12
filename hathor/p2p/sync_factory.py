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
from typing import TYPE_CHECKING

from twisted.internet.task import Clock

from hathor.p2p.sync_manager import SyncManager

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncManagerFactory(ABC):
    @abstractmethod
    def create_sync_manager(self, protocol: 'HathorProtocol', reactor: Clock = None) -> SyncManager:
        pass
