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


from dataclasses import dataclass
from enum import Enum

from hathor.p2p.peer_endpoint import PeerEndpoint

class ConnectionType(Enum):
    """ Types of Connection as inputs for an instance of the Hathor Protocol. """
    OUTGOING = 0
    INCOMING = 1
    BOOTSTRAP = 2
    CHECK_ENTRYPOINTS = 3

    # If a connection comes from an entrypoint queue, if its assigned the
    # 'REBOUNDED' state. It is not a slot.
    REBOUNDED = 4

    def is_outbound(self) -> bool:
        return self.value not in [self.INCOMING]


class ConnectionState(Enum):
    """ State of connection of two peers - either in a slot queue or active. """
    CREATED = 0
    CONNECTING = 1
    READY = 2


@dataclass
class ConnectionAllowed:
    confirmation: str


@dataclass
class ConnectionRejected:
    reason: str


@dataclass
class ConnectionRemoved:
    reason: str
    entrypoint: PeerEndpoint


@dataclass
class ConnectionNotRemoved:
    reason: str
