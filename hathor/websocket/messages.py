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

from typing import Any, Literal, Optional

from hathor.utils.pydantic import BaseModel


class WebSocketMessage(BaseModel):
    pass


class WebSocketErrorMessage(WebSocketMessage):
    type: Literal['error'] = 'error'
    success: Literal[False] = False
    errmsg: str


class CapabilitiesMessage(WebSocketMessage):
    type: Literal['capabilities'] = 'capabilities'
    capabilities: list[str]


class StreamBase(WebSocketMessage):
    pass


class StreamErrorMessage(StreamBase):
    type: Literal['stream:history:error'] = 'stream:history:error'
    id: str
    errmsg: str


class StreamBeginMessage(StreamBase):
    type: Literal['stream:history:begin'] = 'stream:history:begin'
    id: str
    seq: int
    window_size: Optional[int]


class StreamEndMessage(StreamBase):
    type: Literal['stream:history:end'] = 'stream:history:end'
    id: str
    seq: int


class StreamVertexMessage(StreamBase):
    type: Literal['stream:history:vertex'] = 'stream:history:vertex'
    id: str
    seq: int
    data: dict[str, Any]


class StreamAddressMessage(StreamBase):
    type: Literal['stream:history:address'] = 'stream:history:address'
    id: str
    seq: int
    index: int
    address: str
    subscribed: bool
