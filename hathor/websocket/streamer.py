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

from typing import TYPE_CHECKING, Optional

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IPushProducer
from twisted.internet.task import deferLater
from zope.interface import implementer

from hathor.websocket.iterators import AddressItem, AddressSearch, VertexItem
from hathor.websocket.messages import (
    StreamAddressMessage,
    StreamBase,
    StreamBeginMessage,
    StreamEndMessage,
    StreamErrorMessage,
    StreamVertexMessage,
)

if TYPE_CHECKING:
    from hathor.websocket.protocol import HathorAdminWebsocketProtocol


@implementer(IPushProducer)
class HistoryStreamer:
    """A producer that pushes addresses and transactions to a websocket connection.
    Each pushed address is automatically subscribed for real-time updates.

    Streaming messages:

    1. `stream:history:begin`: mark the beginning of a streaming.
    2. `stream:history:address`: mark the beginning of a new address.
    3. `stream:history:vertex`: vertex information in JSON format.
    4. `stream:history:vertex`: vertex information in JSON format.
    5. `stream:history:vertex`: vertex information in JSON format.
    6. `stream:history:vertex`: vertex information in JSON format.
    7. `stream:history:address`: mark the beginning of another address, so the previous address has been finished.
    8. `stream:history:address`: mark the beginning of another address, so the previous address has been finished.
    9. `stream:history:address`: mark the beginning of another address, so the previous address has been finished.
    10. `stream:history:end`: mark the end of the streaming.

    Notice that the streaming might send two or more `address` messages in a row if there are empty addresses.
    """

    STATS_LOG_INTERVAL = 10_000
    DEFAULT_SLIDING_WINDOW_SIZE = None

    def __init__(self,
                 *,
                 protocol: 'HathorAdminWebsocketProtocol',
                 stream_id: str,
                 search: AddressSearch) -> None:
        self.protocol = protocol
        self.stream_id = stream_id
        self.search_iter = aiter(search)

        self.reactor = self.protocol.factory.manager.reactor

        self.max_seconds_locking_event_loop = 1

        self.deferred: Deferred[bool] = Deferred()

        # Statistics.
        self.stats_log_interval = self.STATS_LOG_INTERVAL
        self.stats_total_messages: int = 0
        self.stats_sent_addresses: int = 0
        self.stats_sent_vertices: int = 0

        # Execution control.
        self._started = False
        self._is_running = False
        self._paused = False
        self._stop = False

        # Flow control.
        self._next_sequence_number: int = 0
        self._last_ack: int = -1
        self._sliding_window_size: Optional[int] = self.DEFAULT_SLIDING_WINDOW_SIZE

    def set_sliding_window_size(self, size: Optional[int]) -> None:
        """Set a new sliding window size for flow control. If size is none, disables flow control.
        """
        if size == self._sliding_window_size:
            return
        self._sliding_window_size = size
        self.resume_if_possible()

    def set_ack(self, ack: int) -> None:
        """Set the ack value for flow control.

        If the new value is bigger than the previous value, the streaming might be resumed.
        """
        if ack <= self._last_ack:
            # We might receive outdated or duplicate ACKs, and we can safely ignore them.
            return
        if ack >= self._next_sequence_number:
            # Should we raise an exception here?
            return
        self._last_ack = ack
        self.resume_if_possible()

    def resume_if_possible(self) -> None:
        if not self._started:
            return
        if not self.should_pause_streaming() and not self._is_running:
            self.resumeProducing()

    def start(self) -> Deferred[bool]:
        """Start streaming items."""
        # The websocket connection somehow instantiates an twisted.web.http.HTTPChannel object
        # which register a producer. It seems the HTTPChannel is not used anymore after switching
        # to websocket but it keep registered. So we have to unregister before registering  a new
        # producer.
        if self.protocol.transport.producer:
            self.protocol.unregisterProducer()

        self.protocol.registerProducer(self, True)

        assert not self._started
        self._started = True
        self.send_message(StreamBeginMessage(id=self.stream_id, sliding_window_size=self._sliding_window_size))
        self.resumeProducing()
        return self.deferred

    def stop(self, success: bool) -> None:
        """Stop streaming items."""
        assert self._started
        self._stop = True
        self._started = False
        self.protocol.unregisterProducer()
        self.deferred.callback(success)

    def pauseProducing(self) -> None:
        """Pause streaming. Called by twisted."""
        self._paused = True

    def stopProducing(self) -> None:
        """Stop streaming. Called by twisted."""
        self._stop = True
        self.stop(False)

    def resumeProducing(self) -> None:
        """Resume streaming. Called by twisted."""
        self._paused = False
        self._run()

    def _run(self) -> None:
        """Run the streaming main loop."""
        coro = self._async_run()
        Deferred.fromCoroutine(coro)

    def should_pause_streaming(self) -> bool:
        if self._sliding_window_size is None:
            return False
        stop_value = self._last_ack + self._sliding_window_size + 1
        if self._next_sequence_number < stop_value:
            return False
        return True

    async def _async_run(self):
        assert not self._is_running
        self._is_running = True
        try:
            await self._async_run_unsafe()
        finally:
            self._is_running = False

    async def _async_run_unsafe(self):
        """Internal method that runs the streaming main loop."""
        t0 = self.reactor.seconds()

        async for item in self.search_iter:
            match item:
                case AddressItem():
                    subscribed, errmsg = self.protocol.subscribe_address(item.address)

                    if not subscribed:
                        self.send_message(StreamErrorMessage(
                            id=self.stream_id,
                            errmsg=f'Address subscription failed: {errmsg}'
                        ))
                        self.stop(False)
                        return

                    self.stats_sent_addresses += 1
                    self.send_message(StreamAddressMessage(
                        id=self.stream_id,
                        seq=self._next_sequence_number,
                        index=item.index,
                        address=item.address,
                        subscribed=subscribed,
                    ))

                case VertexItem():
                    self.stats_sent_vertices += 1
                    self.send_message(StreamVertexMessage(
                        id=self.stream_id,
                        seq=self._next_sequence_number,
                        data=item.vertex.to_json_extended(),
                    ))

                case _:
                    assert False

            self._next_sequence_number += 1
            if self.should_pause_streaming():
                break

            # The methods `pauseProducing()` and `stopProducing()` might be called during the
            # call to `self.protocol.sendMessage()`. So both `_paused` and `_stop` might change
            # during the loop.
            if self._paused or self._stop:
                break

            self.stats_total_messages += 1
            if self.stats_total_messages % self.stats_log_interval == 0:
                self.protocol.log.info('websocket streaming statistics',
                                       total_messages=self.stats_total_messages,
                                       sent_vertices=self.stats_sent_vertices,
                                       sent_addresses=self.stats_sent_addresses)

            dt = self.reactor.seconds() - t0
            if dt > self.max_seconds_locking_event_loop:
                # Let the event loop run at least once.
                await deferLater(self.reactor, 0, lambda: None)
                t0 = self.reactor.seconds()

        else:
            if self._stop:
                # If the streamer has been stopped, there is nothing else to do.
                return
            self.send_message(StreamEndMessage(id=self.stream_id))
            self.stop(True)

    def send_message(self, message: StreamBase) -> None:
        """Send a message to the websocket connection."""
        payload = message.json_dumpb()
        self.protocol.sendMessage(payload)
