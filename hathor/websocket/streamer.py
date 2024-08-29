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

from typing import TYPE_CHECKING

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
from hathor.util import json_loadb

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

    def __init__(self,
                 *,
                 protocol: 'HathorAdminWebsocketProtocol',
                 stream_id: str,
                 search: AddressSearch) -> None:
        self.protocol = protocol
        self.stream_id = stream_id
        self.search_iter = aiter(search)

        self.reactor = self.protocol.factory.manager.reactor
        self.tx_storage = self.protocol.factory.manager.tx_storage

        self.max_seconds_locking_event_loop = 1

        self.stats_log_interval = self.STATS_LOG_INTERVAL
        self.stats_total_messages: int = 0
        self.stats_sent_addresses: int = 0
        self.stats_sent_vertices: int = 0

        self._paused = False
        self._stop = False

    def start(self) -> Deferred[bool]:
        """Start streaming items."""
        self.send_message(StreamBeginMessage(id=self.stream_id))

        # The websocket connection somehow instantiates an twisted.web.http.HTTPChannel object
        # which register a producer. It seems the HTTPChannel is not used anymore after switching
        # to websocket but it keep registered. So we have to unregister before registering  a new
        # producer.
        if self.protocol.transport.producer:
            self.protocol.unregisterProducer()

        self.protocol.registerProducer(self, True)
        self.deferred: Deferred[bool] = Deferred()
        self.resumeProducing()
        return self.deferred

    def stop(self, success: bool) -> None:
        """Stop streaming items."""
        self._stop = True
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

    async def _async_run(self):
        """Internal method that runs the streaming main loop."""
        t0 = self.reactor.seconds()
        assert self.tx_storage.indexes.json_extended_cache is not None
        json_extended_cache = self.tx_storage.indexes.json_extended_cache

        async for item in self.search_iter:
            # The methods `pauseProducing()` and `stopProducing()` might be called during the
            # call to `self.protocol.sendMessage()`. So both `_paused` and `_stop` might change
            # during the loop.
            if self._paused or self._stop:
                break

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
                        index=item.index,
                        address=item.address,
                        subscribed=subscribed,
                    ))

                case VertexItem():
                    self.stats_sent_vertices += 1
                    data = json_extended_cache.get_with_cache(item.vertex_id, self.tx_storage)
                    assert data is not None
                    self.send_message(StreamVertexMessage(
                        id=self.stream_id,
                        data=json_loadb(data),
                    ))

                case _:
                    assert False

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
