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


class SingleRequestResponseCommand(Generic[T]):
    """
    Abstraction class that represents a P2P command that is of the "single request-response" kind, that is, a request
    command is sent and then later a response command may be received, completing the previously sent request.
    This class is generic over the type of the expected response.
    """
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
        """
        Create a new command instance.

        Args:
            message_sender: a function that receives a message type and a payload and sends it to some protocol.
            request_message: the message type that represents a request for this command.
        """
        self._message_sender = message_sender
        self._request_message = request_message
        self._deferred_response = None

    def request_data(self, payload: Optional[str] = None) -> Deferred[T]:
        """
        Request data from the command. Note: cannot be called again before a response is received.

        Args:
            payload: an optional payload to be sent to the protocol.

        Returns: a deferred result that may eventually be completed if a response is received.
        """
        assert self._deferred_response is None, 'cannot request data, fetch already in progress'
        self._deferred_response = Deferred()
        self._message_sender(self._request_message, payload)
        return self._deferred_response

    def receive_response(self, data: T) -> bool:
        """
        Complete the request by making the command receive a response.

        Args:
            data: the response to complete the request with.

        Returns: a bool indicating whether the response was received or not, that is, True if there was a request
        waiting for completion, or False otherwise.
        """
        deferred = self._deferred_response
        self._deferred_response = None

        if deferred is None:
            return False

        deferred.callback(data)
        return True


class MultipleRequestResponseCommand(Generic[K, T]):
    """
    Abstraction class that represents a P2P command that is of the "multiple request-response" kind, that is, it stores
    multiple request commands that are sent and then later some response commands may be received, completing the
    previously sent requests.
    This class is generic over the type of the expected response and a key to index each individual request.
    """
    __slots__ = ('_message_sender', '_request_message', '_request_cmds')

    _message_sender: Callable[[ProtocolMessages, Optional[str]], None]
    _request_message: ProtocolMessages
    _request_cmds: dict[K, SingleRequestResponseCommand[T]]

    def __init__(
        self,
        *,
        message_sender: Callable[[ProtocolMessages, Optional[str]], None],
        request_message: ProtocolMessages,
    ) -> None:
        """
        Create a new command instance.

        Args:
            message_sender: a function that receives a message type and a payload and sends it to some protocol.
            request_message: the message type that represents a request for this command.
        """
        self._message_sender = message_sender
        self._request_message = request_message
        self._request_cmds = {}

    def request_data(self, key: K, payload: Optional[str] = None) -> Deferred[T]:
        """
        Request data from the command with a specific key.
        Note: cannot be called again for the same key before a response is received.

        Args:
            key: a key that indexes each individual request.
            payload: an optional payload to be sent to the protocol.

        Returns: a deferred result that may eventually be completed if a response is received for that key.
        """
        assert self._request_cmds.get(key) is None, 'cannot request data, fetch already in progress'

        request_cmd = SingleRequestResponseCommand[T](
            message_sender=self._message_sender,
            request_message=self._request_message
        )
        self._request_cmds[key] = request_cmd

        return request_cmd.request_data(payload)

    def receive_response(self, key: K, data: T) -> bool:
        """
        Complete a request by making the command receive a response for a specific key.

        Args:
            key: a key that indexes each individual request.
            data: the response to complete the request with.

        Returns: a bool indicating whether the response was received or not, that is, True if there was a request
        waiting for completion, or False otherwise.
        """
        request_cmd = self._request_cmds.pop(key, None)

        if request_cmd is None:
            return False

        request_cmd.receive_response(data)
        return True
