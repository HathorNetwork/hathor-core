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

from hathor.event.websocket.request import AckRequest, StartStreamRequest, StopStreamRequest
from hathor.event.websocket.response import InvalidRequestType
from hathor.simulator.trigger import StopAfterNMinedBlocks
from hathor_tests.event.event_simulation_tester import BaseEventSimulationTester


class EventSimulationResponsesTest(BaseEventSimulationTester):
    def test_no_start_no_blocks(self) -> None:
        self.simulator.run(36000)

        responses = self._get_success_responses()

        assert len(responses) == 0  # no events because not started

    def test_start_no_blocks(self) -> None:
        start_stream = StartStreamRequest(type='START_STREAM', window_size=8, last_ack_event_id=None)
        self._send_request(start_stream)
        self.simulator.run(36000)

        responses = self._get_success_responses()

        assert len(responses) == 5  # genesis events
        assert responses[0].event.id == 0  # no ack, so we get from the first event

    def test_start_no_blocks_with_ack(self) -> None:
        start_stream = StartStreamRequest(type='START_STREAM', window_size=8, last_ack_event_id=2)
        self._send_request(start_stream)
        self.simulator.run(36000)

        responses = self._get_success_responses()

        assert len(responses) == 2  # genesis events 3 and 4
        assert responses[0].event.id == 3  # ack=2, so we get from event 3

    def test_no_start_with_blocks(self) -> None:
        miner = self.simulator.create_miner(self.manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterNMinedBlocks(miner, quantity=100)
        self.simulator.run(36000, trigger=trigger)

        responses = self._get_success_responses()

        assert len(responses) == 0  # no events because not started

    def test_start_pre_blocks(self) -> None:
        start_stream = StartStreamRequest(type='START_STREAM', window_size=8, last_ack_event_id=None)
        self._send_request(start_stream)
        self.simulator.run(36000)

        miner = self.simulator.create_miner(self.manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterNMinedBlocks(miner, quantity=100)
        self.simulator.run(36000, trigger=trigger)

        responses = self._get_success_responses()

        assert len(responses) == 8  # 8 events because of window size
        assert responses[0].event.id == 0  # no ack, so we get from the first event

    def test_start_pre_blocks_with_ack(self) -> None:
        start_stream = StartStreamRequest(type='START_STREAM', window_size=8, last_ack_event_id=6)
        self._send_request(start_stream)
        self.simulator.run(36000)

        miner = self.simulator.create_miner(self.manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterNMinedBlocks(miner, quantity=100)
        self.simulator.run(36000, trigger=trigger)

        responses = self._get_success_responses()

        assert len(responses) == 8  # 8 events because of window size
        assert responses[0].event.id == 7  # ack=6, so we get from event 7

    def test_start_post_blocks(self) -> None:
        miner = self.simulator.create_miner(self.manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterNMinedBlocks(miner, quantity=100)
        self.simulator.run(36000, trigger=trigger)

        start_stream = StartStreamRequest(type='START_STREAM', window_size=8, last_ack_event_id=None)
        self._send_request(start_stream)
        self.simulator.run(36000)

        responses = self._get_success_responses()

        assert len(responses) == 8  # 8 events because of window size
        assert responses[0].event.id == 0  # no ack, so we get from the first event

    def test_start_post_blocks_with_ack(self) -> None:
        miner = self.simulator.create_miner(self.manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterNMinedBlocks(miner, quantity=100)
        self.simulator.run(36000, trigger=trigger)

        start_stream = StartStreamRequest(type='START_STREAM', window_size=8, last_ack_event_id=48)
        self._send_request(start_stream)
        self.simulator.run(36000)

        responses = self._get_success_responses()

        assert len(responses) == 8  # 8 events because of window size
        assert responses[0].event.id == 49  # ack=48, so we get from event 49

    def test_restart(self) -> None:
        # start the event stream
        start_stream = StartStreamRequest(type='START_STREAM', window_size=100, last_ack_event_id=None)
        self._send_request(start_stream)
        self.simulator.run(36000)

        # generate 10 blocks
        miner = self.simulator.create_miner(self.manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterNMinedBlocks(miner, quantity=10)
        self.simulator.run(36000, trigger=trigger)

        # get responses
        responses = self._get_success_responses()

        # genesis events (5)
        # + VERTEX_METADATA_CHANGED, one for each genesis tx (2) and for the genesis block (1)
        # + one NEW_VERTEX_ACCEPTED and one VERTEX_METADATA_CHANGED for each new block (2*10)
        # there are free slots in window_size
        assert len(responses) == 5 + 3 + 2 * 10  # = 28
        assert responses[0].event.id == 0  # no ack, so we get from the first event

        # stop the event stream
        stop_stream = StopStreamRequest(type='STOP_STREAM')
        self._send_request(stop_stream)

        # generate 10 blocks
        trigger.reset()
        self.simulator.run(36000, trigger=trigger)

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 0  # no events because stream is stopped

        # stop generating blocks
        miner.stop()

        # restart event stream
        self._send_request(start_stream)
        self.simulator.run(36000)

        # get responses
        responses = self._get_success_responses()

        # events from before (28)
        # + one NEW_VERTEX_ACCEPTED and one VERTEX_METADATA_CHANGED for each new block (2*10)
        assert len(responses) == 28 + 2 * 10
        assert responses[0].event.id == 0  # no ack, so we get from the first event

    def test_restart_with_ack(self) -> None:
        # start the event stream
        start_stream = StartStreamRequest(type='START_STREAM', window_size=100, last_ack_event_id=None)
        self._send_request(start_stream)
        self.simulator.run(36000)

        # generate 10 blocks
        miner = self.simulator.create_miner(self.manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterNMinedBlocks(miner, quantity=10)
        self.simulator.run(36000, trigger=trigger)

        # get responses
        responses = self._get_success_responses()

        # genesis events (5)
        # + VERTEX_METADATA_CHANGED, one for each genesis tx (2) and for the genesis block (1)
        # + one NEW_VERTEX_ACCEPTED and one VERTEX_METADATA_CHANGED for each new block (2*10)
        # there are free slots in window_size
        assert len(responses) == 5 + 3 + 2 * 10  # = 28
        assert responses[0].event.id == 0  # no ack, so we get from the first event

        # stop the event stream
        stop_stream = StopStreamRequest(type='STOP_STREAM')
        self._send_request(stop_stream)

        # generate 10 blocks
        trigger.reset()
        self.simulator.run(36000, trigger=trigger)

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 0  # no events because stream is stopped

        # stop generating blocks
        miner.stop()

        # restart event stream from last event
        start_stream = StartStreamRequest(type='START_STREAM', window_size=100, last_ack_event_id=27)
        self._send_request(start_stream)
        self.simulator.run(36000)

        # get responses
        responses = self._get_success_responses()

        # one NEW_VERTEX_ACCEPTED and one VERTEX_METADATA_CHANGED for each new block (2*10)
        assert len(responses) == 2 * 10
        assert responses[0].event.id == 28  # ack=27, so we get from event 28

    def test_restart_with_ack_too_small(self) -> None:
        # start the event stream
        start_stream = StartStreamRequest(type='START_STREAM', window_size=100, last_ack_event_id=None)
        self._send_request(start_stream)
        self.simulator.run(36000)

        # generate 10 blocks
        miner = self.simulator.create_miner(self.manager, hashpower=1e6)

        trigger = StopAfterNMinedBlocks(miner, quantity=10)
        miner.start()
        self.simulator.run(36000, trigger=trigger)
        miner.stop()

        # get responses
        responses = self._get_success_responses()

        # genesis events (5)
        # + VERTEX_METADATA_CHANGED, one for each genesis tx (2) and for the genesis block (1)
        # + one NEW_VERTEX_ACCEPTED and one VERTEX_METADATA_CHANGED for each new block (2*10)
        # there are free slots in window_size
        assert len(responses) == 5 + 3 + 2 * 10  # = 28
        assert responses[0].event.id == 0  # no ack, so we get from the first event

        # ack all received events
        ack = AckRequest(type='ACK', window_size=100, ack_event_id=27)
        self._send_request(ack)
        self.simulator.run(36000)

        # stop the event stream
        stop_stream = StopStreamRequest(type='STOP_STREAM')
        self._send_request(stop_stream)

        # generate 10 blocks
        trigger.reset()
        miner.start()
        self.simulator.run(36000, trigger=trigger)
        miner.stop()

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 0  # no events because stream is stopped

        # stop generating blocks
        miner.stop()

        # restart event stream from ack too small
        start_stream = StartStreamRequest(type='START_STREAM', window_size=100, last_ack_event_id=10)
        self._send_request(start_stream)
        self.simulator.run(36000)

        # get response
        response = self._get_error_response()

        assert str(response.type) == InvalidRequestType.ACK_TOO_SMALL.value

    def test_multiple_interactions(self) -> None:
        miner = self.simulator.create_miner(self.manager, hashpower=1e6)

        # generate 10 blocks
        trigger = StopAfterNMinedBlocks(miner, quantity=10)
        miner.start()
        self.simulator.run(36000, trigger=trigger)
        miner.stop()

        # start the event stream
        start_stream = StartStreamRequest(type='START_STREAM', window_size=1, last_ack_event_id=None)
        self._send_request(start_stream)
        self.simulator.run(36000)

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 1  # 1 event because of window size
        assert responses[0].event.id == 0  # no ack, so we get the first event

        # ack event
        ack = AckRequest(type='ACK', window_size=1, ack_event_id=0)
        self._send_request(ack)
        self.simulator.run(36000)

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 1  # 1 event because of window size
        assert responses[0].event.id == 1  # ack=0, so we get from event 1

        # increase window size
        ack = AckRequest(type='ACK', window_size=4, ack_event_id=1)
        self._send_request(ack)
        self.simulator.run(36000)

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 4  # 4 events because of window size
        assert responses[0].event.id == 2  # ack=1, so we get from event 2

        # same ack
        self._send_request(ack)
        self.simulator.run(36000)

        # get response
        response = self._get_error_response()

        # ACK too small because we've already sent it
        assert str(response.type) == InvalidRequestType.ACK_TOO_SMALL.value

        # new ack
        ack = AckRequest(type='ACK', window_size=4, ack_event_id=5)
        self._send_request(ack)
        self.simulator.run(36000)

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 4  # 4 events because of window size
        assert responses[0].event.id == 6  # ack=5, so we get from event 6

        # if we had failed processing some of the previous events, we wouldn't ACK all of them
        ack = AckRequest(type='ACK', window_size=4, ack_event_id=7)
        self._send_request(ack)
        self.simulator.run(36000)

        # get responses
        responses = self._get_success_responses()

        assert len(responses) == 4  # 4 events because of window size
        assert responses[0].event.id == 8  # ack=7, so we get from event 8
