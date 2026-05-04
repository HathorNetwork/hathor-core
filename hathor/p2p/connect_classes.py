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


class ConnectionType(Enum):
    """ Types of Connection as inputs for an instance of the Hathor Protocol. """
    OUTGOING = 0
    INCOMING = 1
    BOOTSTRAP = 2

    def is_outbound(self) -> bool:
        """ If value is 1, then the connection is inbound. If not, outbound."""
        return self in (ConnectionType.OUTGOING, ConnectionType.BOOTSTRAP)


@dataclass(slots=True, frozen=True)
class ConnectionAllowed:
    confirmation: str


@dataclass(slots=True, frozen=True)
class ConnectionRejected:
    reason: str


@dataclass(slots=True, frozen=True)
class ConnectionRemoved:
    reason: str


@dataclass(slots=True, frozen=True)
class ConnectionNotRemoved:
    reason: str
