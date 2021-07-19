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

from abc import ABC, abstractmethod, abstractproperty
from typing import Callable, Dict

from hathor.p2p.messages import ProtocolMessages
from hathor.transaction import BaseTransaction


class SyncManager(ABC):
    @abstractproperty
    def is_started(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_cmd_dict(self) -> Dict[ProtocolMessages, Callable[[str], None]]:
        raise NotImplementedError

    @abstractmethod
    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    @abstractmethod
    def is_synced(self) -> bool:
        raise NotImplementedError
