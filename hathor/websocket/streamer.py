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

from enum import Enum, auto
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


class StreamerState(Enum):
    NOT_STARTED = auto()
    ACTIVE = auto()
    PAUSED = auto()
    CLOSING = auto()
    CLOSED = auto()

    def can_transition_to(self, destination: 'StreamerState') -> bool:
        """Checks if the transition to the destination state is valid."""
        return destination in VALID_TRANSITIONS[self]


VALID_TRANSITIONS = {
    StreamerState.NOT_STARTED: {StreamerState.ACTIVE},
    StreamerState.ACTIVE: {StreamerState.ACTIVE, StreamerState.PAUSED, StreamerState.CLOSING, StreamerState.CLOSED},
    StreamerState.PAUSED: {StreamerState.ACTIVE, StreamerState.PAUSED, StreamerState.CLOSED},
    StreamerState.CLOSING: {StreamerState.CLOSED},
    StreamerState.CLOSED: set()
}


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

        # Statistics
        # ----------
        self.stats_log_interval = self.STATS_LOG_INTERVAL
        self.stats_total_messages: int = 0
        self.stats_sent_addresses: int = 0
        self.stats_sent_vertices: int = 0

        # Execution control
        # -----------------
        self._state = StreamerState.NOT_STARTED
        # Used to mark that the streamer is currently running its main loop and sending messages.
        self._is_main_loop_running = False

        # Flow control
        # ------------
        self._next_sequence_number: int = 0
        self._last_ack: int = -1
        self._sliding_window_size: Optional[int] = self.DEFAULT_SLIDING_WINDOW_SIZE

    def get_next_seq(self) -> int:
        assert self._state is not StreamerState.CLOSING
        assert self._state is not StreamerState.CLOSED
        seq = self._next_sequence_number
        self._next_sequence_number += 1
        return seq

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
        if self._state == StreamerState.CLOSING:
            closing_ack = self._next_sequence_number - 1
            if ack == closing_ack:
                self._last_ack = ack
                self.stop(True)
                return
        if ack == self._last_ack:
            # We might receive outdated or duplicate ACKs, and we can safely ignore them.
            return
        if ack < self._last_ack:
            # ACK got smaller. Something is wrong...
            self.send_message(StreamErrorMessage(
                id=self.stream_id,
                errmsg=f'Outdated ACK received (ack={ack})'
            ))
            self.stop(False)
            return
        if ack >= self._next_sequence_number:
            # ACK is higher than the last message sent. Something is wrong...
            self.send_message(StreamErrorMessage(
                id=self.stream_id,
                errmsg=f'Received ACK is higher than the last sent message (ack={ack})'
            ))
            self.stop(False)
            return
        self._last_ack = ack
        self.resume_if_possible()

    def resume_if_possible(self) -> None:
        """Resume sending messages if possible."""
        if self._state == StreamerState.PAUSED:
            return
        if not self._state.can_transition_to(StreamerState.ACTIVE):
            return
        if self._is_main_loop_running:
            return
        if self.should_pause_streaming():
            return
        self._run()

    def set_state(self, new_state: StreamerState) -> None:
        """Set a new state for the streamer."""
        if self._state == new_state:
            return
        assert self._state.can_transition_to(new_state)
        self._state = new_state

    def start(self) -> Deferred[bool]:
        """Start streaming items."""
        assert self._state == StreamerState.NOT_STARTED

        # The websocket connection somehow instantiates an twisted.web.http.HTTPChannel object
        # which register a producer. It seems the HTTPChannel is not used anymore after switching
        # to websocket but it keep registered. So we have to unregister before registering  a new
        # producer.
        if self.protocol.transport.producer:
            self.protocol.unregisterProducer()
        self.protocol.registerProducer(self, True)

        self.send_message(StreamBeginMessage(
            id=self.stream_id,
            seq=self.get_next_seq(),
            window_size=self._sliding_window_size,
        ))
        self.resume_if_possible()
        return self.deferred

    def stop(self, success: bool) -> None:
        """Stop streaming items."""
        if not self._state.can_transition_to(StreamerState.CLOSED):
            # Do nothing if the streamer has already been stopped.
            self.protocol.log.warn('stop called in an unexpected state', state=self._state)
            return
        self.set_state(StreamerState.CLOSED)
        self.protocol.unregisterProducer()
        self.deferred.callback(success)

    def gracefully_close(self) -> None:
        """Gracefully close the stream by sending the StreamEndMessage and waiting for its ack."""
        if not self._state.can_transition_to(StreamerState.CLOSING):
            return
        self.protocol.log.info('websocket streaming ended, waiting for ACK')
        self.send_message(StreamEndMessage(id=self.stream_id, seq=self.get_next_seq()))
        self.set_state(StreamerState.CLOSING)

    def pauseProducing(self) -> None:
        """Pause streaming. Called by twisted."""
        if not self._state.can_transition_to(StreamerState.PAUSED):
            self.protocol.log.warn('pause requested in an unexpected state', state=self._state)
            return
        self.set_state(StreamerState.PAUSED)

    def stopProducing(self) -> None:
        """Stop streaming. Called by twisted."""
        if not self._state.can_transition_to(StreamerState.CLOSED):
            self.protocol.log.warn('stopped requested in an unexpected state', state=self._state)
            return
        self.stop(False)

    def resumeProducing(self) -> None:
        """Resume streaming. Called by twisted."""
        if not self._state.can_transition_to(StreamerState.ACTIVE):
            self.protocol.log.warn('resume requested in an unexpected state', state=self._state)
            return
        self.set_state(StreamerState.ACTIVE)
        self.resume_if_possible()

    def should_pause_streaming(self) -> bool:
        """Return true if the streaming should pause due to the flow control mechanism."""
        if self._sliding_window_size is None:
            return False
        stop_value = self._last_ack + self._sliding_window_size + 1
        if self._next_sequence_number < stop_value:
            return False
        return True

    def _run(self) -> None:
        """Run the streaming main loop."""
        if not self._state.can_transition_to(StreamerState.ACTIVE):
            self.protocol.log.warn('_run() called in an unexpected state', state=self._state)
            return
        coro = self._async_run()
        Deferred.fromCoroutine(coro)

    async def _async_run(self):
        assert not self._is_main_loop_running
        self.set_state(StreamerState.ACTIVE)
        self._is_main_loop_running = True
        try:
            await self._async_run_unsafe()
        finally:
            self._is_main_loop_running = False

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
                        seq=self.get_next_seq(),
                        index=item.index,
                        address=item.address,
                        subscribed=subscribed,
                    ))

                case VertexItem():
                    self.stats_sent_vertices += 1
                    self.send_message(StreamVertexMessage(
                        id=self.stream_id,
                        seq=self.get_next_seq(),
                        data=item.vertex.to_json_extended(),
                    ))

                case _:
                    assert False

            if self.should_pause_streaming():
                break

            self.stats_total_messages += 1
            if self.stats_total_messages % self.stats_log_interval == 0:
                self.protocol.log.info('websocket streaming statistics',
                                       total_messages=self.stats_total_messages,
                                       sent_vertices=self.stats_sent_vertices,
                                       sent_addresses=self.stats_sent_addresses)

            # The methods `pauseProducing()` and `stopProducing()` might be called during the
            # call to `self.protocol.sendMessage()`. So the streamer state might change during
            # the loop.
            if self._state is not StreamerState.ACTIVE:
                break

            # Limit blocking of the event loop to a maximum of N seconds.
            dt = self.reactor.seconds() - t0
            if dt > self.max_seconds_locking_event_loop:
                # Let the event loop run at least once.
                await deferLater(self.reactor, 0, lambda: None)
                t0 = self.reactor.seconds()

        else:
            # Iterator is empty so we can close the stream.
            self.gracefully_close()

    def send_message(self, message: StreamBase) -> None:
        """Send a message to the websocket connection."""
        payload = message.json_dumpb()
        self.protocol.sendMessage(payload)
