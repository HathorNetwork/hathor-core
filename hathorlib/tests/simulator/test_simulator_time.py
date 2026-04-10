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

"""Tests for time control: advance_time, set_time, time-dependent blueprints."""

import pytest

from hathorlib.nanocontracts.exception import NCFail
from hathorlib.simulator import SimulatorBuilder

from .blueprints import TimeLock


class TestSimulatorTime:
    def test_advance_time(self) -> None:
        sim = SimulatorBuilder().build()
        t0 = sim.clock_time
        sim.advance_time(100)
        assert sim.clock_time == t0 + 100

    def test_set_time(self) -> None:
        sim = SimulatorBuilder().build()
        sim.set_time(999_999)
        assert sim.clock_time == 999_999

    def test_timelock_too_early(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(TimeLock)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice, args=(3600,))
        cid = result.contract_id

        unlock_time = sim.call_view(cid, 'get_unlock_time')
        assert unlock_time > sim.clock_time

        with pytest.raises(NCFail, match='Too early'):
            sim.call_public(cid, 'claim', caller=alice)

    def test_timelock_after_advance(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(TimeLock)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice, args=(3600,))
        cid = result.contract_id

        # Advance past lock time
        sim.advance_time(7200)

        # Should succeed now
        sim.call_public(cid, 'claim', caller=alice)

    def test_time_affects_block_timestamp(self) -> None:
        sim = SimulatorBuilder().with_auto_new_block(False).build()
        bid = sim.register_blueprint(TimeLock)
        alice = sim.create_address('alice')

        sim.set_time(1000)
        result = sim.create_contract(bid, caller=alice, args=(500,))
        cid = result.contract_id

        # unlock_time should be 1000 + 500 = 1500
        assert sim.call_view(cid, 'get_unlock_time') == 1500

        sim.new_block()

        # Set time past unlock
        sim.set_time(2000)
        sim.call_public(cid, 'claim', caller=alice)
