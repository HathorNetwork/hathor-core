#  Copyright 2023 Hathor Labs
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

from typing import Callable, Generic, Optional, TypeVar

from twisted.internet.defer import Deferred

from hathor.p2p.messages import ProtocolMessages

T = TypeVar('T')
K = TypeVar('K')


class RequestResponseCommand(Generic[T]):
    __slots__ = ('_message_sender', '_request_message', '_deferred_response')

    _message_sender: Callable[[ProtocolMessages, Optional[str]], None]
    _request_message: ProtocolMessages
    _deferred_response: Optional[Deferred[T]]

    def __init__(
        self,
        *,
        message_sender: Callable[[ProtocolMessages, Optional[str]], None],
        request_message: ProtocolMessages,
    ) -> None:
        self._message_sender = message_sender
        self._request_message = request_message
        self._deferred_response = None

    def request_data(self, payload: Optional[str] = None) -> Deferred[T]:
        assert self._deferred_response is None, 'cannot request data, fetch already in progress'
        self._deferred_response = Deferred()
        self._message_sender(self._request_message, payload)
        return self._deferred_response

    def receive_response(self, data: T) -> bool:
        deferred = self._deferred_response
        self._deferred_response = None

        if deferred is None:
            return False

        deferred.callback(data)
        return True


class MultipleRequestResponseCommands(Generic[K, T]):
    __slots__ = ('_message_sender', '_request_message', '_request_cmds')

    _message_sender: Callable[[ProtocolMessages, Optional[str]], None]
    _request_message: ProtocolMessages
    _request_cmds: dict[K, RequestResponseCommand[T]]

    def __init__(
        self,
        *,
        message_sender: Callable[[ProtocolMessages, Optional[str]], None],
        request_message: ProtocolMessages,
    ) -> None:
        self._message_sender = message_sender
        self._request_message = request_message
        self._request_cmds = {}

    def request_data(self, key: K, payload: Optional[str] = None) -> Deferred[T]:
        assert self._request_cmds.get(key) is None, 'cannot request data, fetch already in progress'

        request_cmd = RequestResponseCommand[T](
            message_sender=self._message_sender,
            request_message=self._request_message
        )
        self._request_cmds[key] = request_cmd

        return request_cmd.request_data(payload)

    def receive_response(self, key: K, data: T) -> bool:
        request_cmd = self._request_cmds.pop(key, None)

        if request_cmd is None:
            return False

        request_cmd.receive_response(data)
        return True
