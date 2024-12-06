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

from typing import TYPE_CHECKING, Any, Union

from autobahn.twisted.websocket import WebSocketServerProtocol
from structlog import get_logger
from twisted.python.failure import Failure

from hathor.p2p.utils import format_address
from hathor.util import json_dumpb, json_loadb, json_loads
from hathor.websocket.exception import InvalidAddress, InvalidXPub, LimitExceeded
from hathor.websocket.iterators import (
    AddressItem,
    AddressSearch,
    ManualAddressSequencer,
    aiter_xpub_addresses,
    gap_limit_search,
)
from hathor.websocket.messages import CapabilitiesMessage, StreamErrorMessage, WebSocketMessage
from hathor.websocket.streamer import HistoryStreamer

if TYPE_CHECKING:
    from hathor.websocket.factory import HathorAdminWebsocketFactory

logger = get_logger()


class HathorAdminWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol to communicate with admin frontend

        We save a set of connections that we have opened so we
        can send the data update to the clients
    """

    MAX_GAP_LIMIT: int = 10_000
    HISTORY_STREAMING_CAPABILITY: str = 'history-streaming'

    def __init__(self,
                 factory: 'HathorAdminWebsocketFactory',
                 is_history_streaming_enabled: bool) -> None:
        self.log = logger.new()
        self.factory = factory
        super().__init__()

        self.subscribed_to: set[str] = set()

        # Enable/disable history streaming for this connection.
        self.is_history_streaming_enabled = is_history_streaming_enabled
        self._history_streamer: HistoryStreamer | None = None
        self._manual_address_iter: ManualAddressSequencer | None = None

    def get_capabilities(self) -> list[str]:
        """Get a list of websocket capabilities."""
        capabilities = []
        if self.is_history_streaming_enabled:
            capabilities.append(self.HISTORY_STREAMING_CAPABILITY)
        return capabilities

    def send_capabilities(self) -> None:
        """Send a capabilities message."""
        self.send_message(CapabilitiesMessage(capabilities=self.get_capabilities()))

    def disable_history_streaming(self) -> None:
        """Disable history streaming in this connection."""
        self.is_history_streaming_enabled = False
        if self._history_streamer:
            self._history_streamer.stop(success=False)
        self.log.info('websocket history streaming disabled')

    def get_short_remote(self) -> str:
        """Get remote for logging."""
        assert self.transport is not None
        return format_address(self.transport.getPeer())

    def onConnect(self, request):
        """Called by the websocket protocol when the connection is opened but it is still pending handshaking."""
        self.log = logger.new(remote=self.get_short_remote())
        self.log.info('websocket connection opened, starting handshake...')

    def onOpen(self) -> None:
        """Called by the websocket protocol when the connection is established."""
        self.factory.on_client_open(self)
        self.log.info('websocket connection established')
        self.send_capabilities()

    def onClose(self, wasClean, code, reason):
        """Called by the websocket protocol when the connection is closed."""
        self.factory.on_client_close(self)
        self.log.info('websocket connection closed', reason=reason)

    def onMessage(self, payload: Union[bytes, str], isBinary: bool) -> None:
        """Called by the websocket protocol when a new message is received."""
        self.log.debug('new message', payload=payload.hex() if isinstance(payload, bytes) else payload)
        if isinstance(payload, bytes):
            message = json_loadb(payload)
        else:
            message = json_loads(payload)

        _type = message.get('type')

        if _type == 'ping':
            self._handle_ping(message)
        elif _type == 'subscribe_address':
            self.factory._handle_subscribe_address(self, message)
        elif _type == 'unsubscribe_address':
            self.factory._handle_unsubscribe_address(self, message)
        elif _type == 'request:history:xpub':
            self._open_history_xpub_streamer(message)
        elif _type == 'request:history:manual':
            self._handle_history_manual_streamer(message)
        elif _type == 'request:history:stop':
            self._stop_streamer(message)
        elif _type == 'request:history:ack':
            self._ack_streamer(message)

    def _handle_ping(self, message: dict[Any, Any]) -> None:
        """Handle ping message, should respond with a simple {"type": "pong"}"""
        payload = json_dumpb({'type': 'pong'})
        self.sendMessage(payload, False)

    def fail_if_history_streaming_is_disabled(self) -> bool:
        """Return false if the history streamer is enabled. Otherwise, it sends an
        error message and returns true."""
        if self.is_history_streaming_enabled:
            return False

        self.send_message(StreamErrorMessage(
            id='',
            errmsg='Streaming history is disabled.'
        ))
        return True

    def _create_streamer(self, stream_id: str, search: AddressSearch, window_size: int | None) -> None:
        """Create the streamer and handle its callbacks."""
        assert self._history_streamer is None
        self._history_streamer = HistoryStreamer(protocol=self, stream_id=stream_id, search=search)
        if window_size is not None:
            if window_size < 0:
                self._history_streamer.set_sliding_window_size(None)
            else:
                self._history_streamer.set_sliding_window_size(window_size)
        deferred = self._history_streamer.start()
        deferred.addBoth(self._streamer_callback)
        return

    def _open_history_xpub_streamer(self, message: dict[Any, Any]) -> None:
        """Handle request to stream transactions using an xpub."""
        if self.fail_if_history_streaming_is_disabled():
            return

        stream_id = message['id']

        if self._history_streamer is not None:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg='Streaming is already opened.'
            ))
            return

        xpub = message['xpub']
        gap_limit = message.get('gap-limit', 20)
        first_index = message.get('first-index', 0)
        if gap_limit > self.MAX_GAP_LIMIT:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg=f'GAP limit is too big. Maximum: {self.MAX_GAP_LIMIT}'
            ))
            return

        try:
            address_iter = aiter_xpub_addresses(xpub, first_index=first_index)
        except InvalidXPub:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg=f'Invalid XPub: {xpub}'
            ))
            return

        search = gap_limit_search(self.factory.manager, address_iter, gap_limit)
        window_size = message.get('window-size', None)
        self._create_streamer(stream_id, search, window_size)
        self.log.info('opening a websocket xpub streaming',
                      stream_id=stream_id,
                      xpub=xpub,
                      gap_limit=gap_limit,
                      first_index=first_index)

    def _handle_history_manual_streamer(self, message: dict[Any, Any]) -> None:
        """Handle request to stream transactions using a list of addresses."""
        if self.fail_if_history_streaming_is_disabled():
            return

        stream_id = message['id']
        addresses: list[AddressItem] = [AddressItem(idx, address) for idx, address in message.get('addresses', [])]
        first = message.get('first', False)
        last = message.get('last', False)

        if self._history_streamer is not None:
            if first or self._history_streamer.stream_id != stream_id:
                self.send_message(StreamErrorMessage(
                    id=stream_id,
                    errmsg='Streaming is already opened.'
                ))
                return

            if not self._add_addresses_to_manual_iter(stream_id, addresses, last):
                return

            self.log.info('Adding addresses to a websocket manual streaming',
                          stream_id=stream_id,
                          addresses=addresses,
                          last=last)
            return

        gap_limit = message.get('gap-limit', 20)
        if gap_limit > self.MAX_GAP_LIMIT:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg=f'GAP limit is too big. Maximum: {self.MAX_GAP_LIMIT}'
            ))
            return

        if not first:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg='Streaming not found. You must send first=true in your first message.'
            ))
            return

        address_iter = ManualAddressSequencer()
        self._manual_address_iter = address_iter
        if not self._add_addresses_to_manual_iter(stream_id, addresses, last):
            self._manual_address_iter = None
            return

        search = gap_limit_search(self.factory.manager, address_iter, gap_limit)
        window_size = message.get('window-size', None)
        self._create_streamer(stream_id, search, window_size)
        self.log.info('opening a websocket manual streaming',
                      stream_id=stream_id,
                      addresses=addresses,
                      gap_limit=gap_limit,
                      last=last)

    def _streamer_callback(self, result: bool | Failure) -> None:
        """Callback used to identify when the streamer has ended."""
        # TODO: Handle the case when `result` is Failure
        assert self._history_streamer is not None
        self.log.info('websocket xpub streaming has been finished',
                      stream_id=self._history_streamer.stream_id,
                      success=result,
                      sent_addresses=self._history_streamer.stats_sent_addresses,
                      sent_vertices=self._history_streamer.stats_sent_vertices)
        self._history_streamer = None
        self._manual_address_iter = None

    def _stop_streamer(self, message: dict[Any, Any]) -> None:
        """Handle request to stop the current streamer."""
        stream_id: str = message.get('id', '')

        if self._history_streamer is None:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg='No streaming opened.'
            ))
            return

        assert self._history_streamer is not None

        if self._history_streamer.stream_id != stream_id:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg='Current stream has a different id.'
            ))
            return

        self._history_streamer.stop(success=False)
        self.log.info('stopping a websocket xpub streaming', stream_id=stream_id)

    def _ack_streamer(self, message: dict[Any, Any]) -> None:
        """Handle request to set the ack number in the current streamer."""
        stream_id: str = message.get('id', '')

        if self._history_streamer is None:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg='No streaming opened.'
            ))
            return

        assert self._history_streamer is not None

        if self._history_streamer.stream_id != stream_id:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg='Current stream has a different id.'
            ))
            return

        ack = message.get('ack', None)
        if ack is not None:
            if not isinstance(ack, int):
                self.send_message(StreamErrorMessage(
                    id=stream_id,
                    errmsg='Invalid ack.'
                ))
                return
            self.log.info('ack received', stream_id=stream_id, ack=ack)
            self._history_streamer.set_ack(ack)

        window = message.get('window', None)
        if window is not None:
            if not isinstance(window, int):
                self.send_message(StreamErrorMessage(
                    id=stream_id,
                    errmsg='Invalid window.'
                ))
                return
            self.log.info('sliding window size updated', stream_id=stream_id, sliding_window_size=window)
            if window < 0:
                self._history_streamer.set_sliding_window_size(None)
            else:
                self._history_streamer.set_sliding_window_size(window)

    def send_message(self, message: WebSocketMessage) -> None:
        """Send a typed message."""
        payload = message.json_dumpb()
        self.sendMessage(payload)

    def subscribe_address(self, address: str) -> tuple[bool, str]:
        """Subscribe to receive real-time messages for all vertices related to an address."""
        return self.factory.subscribe_address(self, address)

    def _add_addresses_to_manual_iter(self, stream_id: str, addresses: list[AddressItem], last: bool) -> bool:
        """Add addresses to manual address iter and returns true if it succeeds."""
        assert self._manual_address_iter is not None
        try:
            self._manual_address_iter.add_addresses(addresses, last)
        except LimitExceeded:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg='List of addresses is too long.'
            ))
            return False
        except InvalidAddress as exc:
            self.send_message(StreamErrorMessage(
                id=stream_id,
                errmsg=f'Invalid address: {exc}'
            ))
            return False

        self.log.info('Adding addresses to a websocket manual streaming',
                      stream_id=stream_id,
                      addresses=addresses,
                      last=last)
        return True
