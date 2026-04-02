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

"""Tests for snapshot/restore functionality."""

from hathorlib.simulator import SimulatorBuilder

from .blueprints import Counter


class TestSimulatorSnapshot:
    def test_snapshot_and_restore(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        cid = r.contract_id

        sim.call_public(cid, 'increment', caller=alice)
        sim.call_public(cid, 'increment', caller=alice)
        assert sim.call_view(cid, 'get_count') == 2

        snap = sim.snapshot()

        # Mutate further
        sim.call_public(cid, 'increment', caller=alice)
        sim.call_public(cid, 'increment', caller=alice)
        assert sim.call_view(cid, 'get_count') == 4

        # Restore
        sim.restore(snap)
        assert sim.call_view(cid, 'get_count') == 2

    def test_restore_preserves_clock(self) -> None:
        sim = SimulatorBuilder().build()
        sim.set_time(5000)

        snap = sim.snapshot()

        sim.advance_time(1000)
        assert sim.clock_time == 6000

        sim.restore(snap)
        assert sim.clock_time == 5000

    def test_restore_preserves_block_height(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        height_after_create = sim.block_height

        snap = sim.snapshot()

        sim.call_public(r.contract_id, 'increment', caller=alice)
        assert sim.block_height == height_after_create + 1

        sim.restore(snap)
        assert sim.block_height == height_after_create

    def test_multiple_snapshots(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        cid = r.contract_id

        snap0 = sim.snapshot()

        sim.call_public(cid, 'increment', caller=alice)
        snap1 = sim.snapshot()

        sim.call_public(cid, 'increment', caller=alice)
        sim.call_public(cid, 'increment', caller=alice)
        assert sim.call_view(cid, 'get_count') == 3

        sim.restore(snap1)
        assert sim.call_view(cid, 'get_count') == 1

        sim.restore(snap0)
        assert sim.call_view(cid, 'get_count') == 0

    def test_operations_after_restore(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        cid = r.contract_id

        sim.call_public(cid, 'increment', caller=alice)
        snap = sim.snapshot()

        sim.call_public(cid, 'increment', caller=alice)
        sim.restore(snap)

        # Should be able to continue operating after restore
        sim.call_public(cid, 'increment', caller=alice)
        assert sim.call_view(cid, 'get_count') == 2
