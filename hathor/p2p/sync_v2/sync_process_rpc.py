#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from typing import Annotated, Literal, TypeAlias

from pydantic import Field
from typing_extensions import assert_never

from hathor.multiprocess.process_rpc import ProcessRPCHandler
from hathor.utils.pydantic import BaseModel


class RequestA(BaseModel):
    type: Literal['A'] = Field(default='A', const=True)
    a: int


class RequestB(BaseModel):
    type: Literal['B'] = Field(default='B', const=True)
    b: str


class ResponseC(BaseModel):
    type: Literal['C'] = Field(default='C', const=True)
    c: str


Message: TypeAlias = Annotated[RequestA | RequestB | ResponseC, Field(discriminator='type')]


class MessageWrapper(BaseModel):
    """Class that wraps the Request union type for parsing."""
    __root__: Message

    @classmethod
    def deserialize(cls, raw: bytes) -> Message:
        return cls.parse_raw(raw).__root__


class MyProcessRPCHandler(ProcessRPCHandler[Message]):
    def handle_request(self, request: Message) -> Message:
        response: Message
        match request:
            case RequestA():
                response = self._handle_request_a(request)
            case RequestB():
                response = self._handle_request_b(request)
            case ResponseC():
                raise NotImplementedError
            case _:
                assert_never(request)
        return response

    def deserialize(self, data: bytes) -> Message:
        return MessageWrapper.deserialize(data)

    def serialize(self, data: Message) -> bytes:
        return data.json_dumpb()

    @staticmethod
    def _handle_request_a(a: RequestA) -> ResponseC:
        raise NotImplementedError

    @staticmethod
    def _handle_request_b(b: RequestB) -> ResponseC:
        return ResponseC(c=f'res {b.b}')
