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

"""Basic simulator lifecycle tests: create, call, view."""

import pytest

from hathorlib.simulator import SimulatorBuilder

from .blueprints import Counter, FailingBlueprint


class TestSimulatorBasic:
    def test_build_simulator(self) -> None:
        sim = SimulatorBuilder().build()
        assert sim.block_height == 0

    def test_create_address_deterministic(self) -> None:
        sim = SimulatorBuilder().build()
        a1 = sim.create_address('alice')
        a2 = sim.create_address('alice')
        assert a1 == a2

        b = sim.create_address('bob')
        assert a1 != b

    def test_register_blueprint(self) -> None:
        sim = SimulatorBuilder().build()
        bid1 = sim.register_blueprint(Counter)
        bid2 = sim.register_blueprint(Counter)
        assert bid1 == bid2  # idempotent

    def test_create_contract(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice)
        assert result.contract_id is not None
        assert result.tx_hash is not None
        assert result.block_hash is not None
        assert sim.has_contract(result.contract_id)

    def test_call_public_and_view(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice)
        cid = result.contract_id

        assert sim.call_view(cid, 'get_count') == 0

        sim.call_public(cid, 'increment', caller=alice)
        assert sim.call_view(cid, 'get_count') == 1

        sim.call_public(cid, 'increment', caller=alice)
        sim.call_public(cid, 'increment', caller=alice)
        assert sim.call_view(cid, 'get_count') == 3

    def test_multiple_contracts(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r1 = sim.create_contract(bid, caller=alice)
        r2 = sim.create_contract(bid, caller=alice)

        sim.call_public(r1.contract_id, 'increment', caller=alice)
        sim.call_public(r1.contract_id, 'increment', caller=alice)
        sim.call_public(r2.contract_id, 'increment', caller=alice)

        assert sim.call_view(r1.contract_id, 'get_count') == 2
        assert sim.call_view(r2.contract_id, 'get_count') == 1


class TestSimulatorErrors:
    def test_failed_call_does_not_commit(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(FailingBlueprint)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice)
        cid = result.contract_id

        assert sim.call_view(cid, 'get_value') == 42

        # Set a value first
        sim.call_public(cid, 'set_value', caller=alice, args=(100,))
        assert sim.call_view(cid, 'get_value') == 100

        # This should fail and NOT commit
        from hathorlib.nanocontracts.exception import NCFail
        with pytest.raises(NCFail, match='intentional failure'):
            sim.call_public(cid, 'fail_method', caller=alice, args=(0,))

        # Value should still be 100
        assert sim.call_view(cid, 'get_value') == 100

    def test_failed_call_logs_captured(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(FailingBlueprint)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice)

        from hathorlib.nanocontracts.exception import NCFail
        with pytest.raises(NCFail):
            sim.call_public(result.contract_id, 'fail_method', caller=alice, args=(0,))

        # Logs should be captured even for failed calls
        all_logs = sim.get_logs()
        assert len(all_logs) >= 2  # create + failed call
