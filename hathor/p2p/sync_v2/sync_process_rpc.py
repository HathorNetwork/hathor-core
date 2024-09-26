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
from twisted.internet.interfaces import IAddress
from twisted.protocols.basic import LineReceiver
from typing_extensions import assert_never

from hathor.multiprocess.process_rpc import ProcessRPCHandler, ProcessRPC, T
from hathor.p2p.peer import Peer
from hathor.reactor import ReactorProtocol
from hathor.utils.pydantic import BaseModel


class InitProtocol(BaseModel):
    type: Literal['INIT_PROTOCOL'] = Field(default='INIT_PROTOCOL', const=True)


class Success(BaseModel):
    type: Literal['SUCCESS'] = Field(default='SUCCESS', const=True)


class ResponseC(BaseModel):
    type: Literal['C'] = Field(default='C', const=True)
    c: str


Message: TypeAlias = Annotated[InitProtocol | Success | ResponseC, Field(discriminator='type')]


class MessageWrapper(BaseModel):
    """Class that wraps the Request union type for parsing."""
    __root__: Message

    @classmethod
    def deserialize(cls, raw: bytes) -> Message:
        return cls.parse_raw(raw).__root__


class MyProcessRPCHandler(ProcessRPCHandler[Message]):
    def handle_request(self, request: Message) -> Message:
        raise NotImplementedError
        # response: Message
        # match request:
        #     case InitProtocol():
        #         response = self._handle_request_a(request)
        #     case RequestB():
        #         response = self._handle_request_b(request)
        #     case ResponseC():
        #         raise NotImplementedError
        #     case _:
        #         assert_never(request)
        # return response

    def deserialize(self, data: bytes) -> Message:
        return MessageWrapper.deserialize(data)

    def serialize(self, data: Message) -> bytes:
        return data.json_dumpb()


class SyncRPCHandler(ProcessRPCHandler[Message]):
    def handle_request(self, request: Message) -> Message:
        response: Message
        match request:
            case InitProtocol():
                pass
            case _:
                raise AssertionError(request)

    def serialize(self, message: Message) -> bytes:
        raise NotImplementedError

    def deserialize(self, data: bytes) -> Message:
        raise NotImplementedError


class ProcessRPCLineReceiver(LineReceiver):
    __slots__ = ('_rpc', '_protocol',)

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        addr: IAddress,
        network: str,
        my_peer: Peer,
        use_ssl: bool,
        inbound: bool,
    ) -> None:
        self._rpc = ProcessRPC.fork(
            main_reactor=reactor,
            target=self._run_line_receiver,
            subprocess_name=str(addr),
            main_handler=MyProcessRPCHandler(),
            subprocess_handler=SyncRPCHandler()
        )
        # self._protocol = HathorLineReceiver(*args, **kwargs)

    @staticmethod
    async def _run_line_receiver(rpc: ProcessRPC) -> None:
        await rpc.call(InitProtocol())
