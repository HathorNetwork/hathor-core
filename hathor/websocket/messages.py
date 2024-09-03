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

from typing import Any, Optional

from pydantic import Field

from hathor.utils.pydantic import BaseModel


class WebSocketMessage(BaseModel):
    pass


class CapabilitiesMessage(WebSocketMessage):
    type: str = Field('capabilities', const=True)
    capabilities: list[str]


class StreamBase(WebSocketMessage):
    pass


class StreamErrorMessage(StreamBase):
    type: str = Field('stream:history:error', const=True)
    id: str
    errmsg: str


class StreamBeginMessage(StreamBase):
    type: str = Field('stream:history:begin', const=True)
    id: str
    window_size: Optional[int]


class StreamEndMessage(StreamBase):
    type: str = Field('stream:history:end', const=True)
    id: str


class StreamVertexMessage(StreamBase):
    type: str = Field('stream:history:vertex', const=True)
    id: str
    seq: int
    data: dict[str, Any]


class StreamAddressMessage(StreamBase):
    type: str = Field('stream:history:address', const=True)
    id: str
    seq: int
    index: int
    address: str
    subscribed: bool
