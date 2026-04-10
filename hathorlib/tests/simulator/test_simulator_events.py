# Copyright 2026 Hathor Labs
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

"""Tests for event capture and query."""

from hathorlib.simulator import SimulatorBuilder

from .blueprints import Counter, EventEmitter


class TestSimulatorEvents:
    def test_events_in_tx_result(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(EventEmitter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        tx_result = sim.call_public(r.contract_id, 'emit_one', caller=alice)

        assert len(tx_result.events) == 1
        assert tx_result.events[0].data == b'event_one'

    def test_multiple_events(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(EventEmitter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        tx_result = sim.call_public(r.contract_id, 'emit_two', caller=alice)

        assert len(tx_result.events) == 2
        assert tx_result.events[0].data == b'event_a'
        assert tx_result.events[1].data == b'event_b'

    def test_query_events_by_tx_hash(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(EventEmitter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        tx_result = sim.call_public(r.contract_id, 'emit_one', caller=alice)

        events = sim.get_events(tx_hash=tx_result.tx_hash)
        assert len(events) == 1
        assert events[0].data == b'event_one'

    def test_query_events_by_block_hash(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(EventEmitter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        tx_result = sim.call_public(r.contract_id, 'emit_one', caller=alice)

        events = sim.get_events(block_hash=tx_result.block_hash)
        assert len(events) == 1

    def test_query_all_events(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(EventEmitter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        sim.call_public(r.contract_id, 'emit_one', caller=alice)
        sim.call_public(r.contract_id, 'emit_two', caller=alice)

        all_events = sim.get_events()
        assert len(all_events) == 3  # 1 + 2

    def test_no_events_for_method_without_emit(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        tx_result = sim.call_public(r.contract_id, 'increment', caller=alice)

        assert len(tx_result.events) == 0

    def test_events_with_increment_and_emit(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        tx_result = sim.call_public(r.contract_id, 'increment_and_emit', caller=alice)

        assert len(tx_result.events) == 1
        assert tx_result.events[0].data == b'incremented'
        assert sim.call_view(r.contract_id, 'get_count') == 1


class TestSimulatorLogs:
    def test_logs_by_tx_hash(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        tx_result = sim.call_public(r.contract_id, 'increment', caller=alice)

        logs = sim.get_logs(tx_hash=tx_result.tx_hash)
        assert len(logs) == 1
        assert logs[0].error_traceback is None

    def test_all_logs(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        sim.call_public(r.contract_id, 'increment', caller=alice)
        sim.call_public(r.contract_id, 'increment', caller=alice)

        all_logs = sim.get_logs()
        assert len(all_logs) == 3  # create + 2 increments

    def test_logs_by_block_hash(self) -> None:
        sim = SimulatorBuilder().with_auto_new_block(False).build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        sim.call_public(r.contract_id, 'increment', caller=alice)
        block_result = sim.new_block()

        logs = sim.get_logs(block_hash=block_result.block_hash)
        assert len(logs) == 2  # create + increment
