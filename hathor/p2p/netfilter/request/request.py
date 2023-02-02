# Copyright 2023 Hathor Labs
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

from __future__ import annotations

from typing import Dict, Any, Literal, Union, Annotated
from typing import TypeVar, Generic, Type

from pydantic import Field
from pydantic.generics import GenericModel

from hathor.p2p.netfilter.matches import NetfilterMatchOr, NetfilterMatchIPAddress, NetfilterMatchPeerId, \
    NetfilterMatchAll, NetfilterMatchAnd
from hathor.p2p.netfilter.matches_remote import NetfilterMatchRemoteURL
from hathor.util import Reactor
from hathor.utils.pydantic import BaseModel

ModelT = TypeVar('ModelT')


class Params(GenericModel, Generic[ModelT]):
    _model_class: Type[ModelT]

    def build(self) -> ModelT:
        return self._model_class(**self.dict())


class NetfilterMatchAllParams(BaseModel, Params):
    _model_class = NetfilterMatchAll


class NetfilterMatchAndParams(BaseModel, Params):
    _model_class = NetfilterMatchAnd
    a: MatchRequest
    b: MatchRequest


class NetfilterMatchOrParams(BaseModel, Params):
    _model_class = NetfilterMatchOr
    a: MatchRequest
    b: MatchRequest


class NetfilterMatchIPAddressParams(BaseModel, Params):
    _model_class = NetfilterMatchIPAddress
    host: str


class NetfilterMatchPeerIdParams(BaseModel, Params):
    _model_class = NetfilterMatchPeerId
    peer_id: str


class NetfilterMatchRemoteURLParams(BaseModel, Params):
    _model_class = NetfilterMatchRemoteURL
    name: str
    reactor: Reactor
    url: str
    update_interval: int = 30


class ChainRequest(BaseModel):
    name: str


class TargetRequest(BaseModel):
    type: str
    target_params: Dict[str, Any]


TypeLiteralT = TypeVar('TypeLiteralT')
ParamsT = TypeVar('ParamsT')


class GenericMatchRequest(GenericModel, Generic[TypeLiteralT, ParamsT]):
    type: TypeLiteralT
    match_params: ParamsT


# TODO: Move constants to Enum?
MatchRequestUnion = Union[
    GenericMatchRequest[Literal['NetfilterMatchOr'], NetfilterMatchOrParams],
    GenericMatchRequest[Literal['NetfilterMatchPeerId'], NetfilterMatchPeerIdParams],
    GenericMatchRequest[Literal['NetfilterMatchIPAddress'], NetfilterMatchIPAddressParams]
]

MatchRequest = Annotated[MatchRequestUnion, Field(discriminator='type')]


class NetFilterRequest(BaseModel):
    chain: ChainRequest
    match: MatchRequest
    target: TargetRequest
