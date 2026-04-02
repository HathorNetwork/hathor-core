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

"""Tests for block lifecycle: auto_new_block, multi-tx blocks."""

from hathorlib.simulator import SimulatorBuilder

from .blueprints import Counter


class TestSimulatorBlocks:
    def test_auto_new_block_true(self) -> None:
        sim = SimulatorBuilder().build()  # auto_new_block=True by default
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        initial_height = sim.block_height
        sim.create_contract(bid, caller=alice)
        # auto_new_block advances the block
        assert sim.block_height == initial_height + 1

    def test_auto_new_block_false(self) -> None:
        sim = SimulatorBuilder().with_auto_new_block(False).build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice)
        cid = result.contract_id

        sim.call_public(cid, 'increment', caller=alice)
        sim.call_public(cid, 'increment', caller=alice)

        # Block hasn't advanced yet
        block_result = sim.new_block()
        assert len(block_result.tx_results) == 3  # create + 2 increments
        assert block_result.block_height > 0

        assert sim.call_view(cid, 'get_count') == 2

    def test_multi_tx_same_block(self) -> None:
        sim = SimulatorBuilder().with_auto_new_block(False).build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        cid = r.contract_id

        # All in the same block
        for _ in range(5):
            sim.call_public(cid, 'increment', caller=alice)

        block_result = sim.new_block()
        assert len(block_result.tx_results) == 6  # create + 5 increments

        assert sim.call_view(cid, 'get_count') == 5

    def test_toggle_auto_new_block(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        r = sim.create_contract(bid, caller=alice)
        cid = r.contract_id

        # Switch to manual blocks
        sim.auto_new_block = False
        sim.call_public(cid, 'increment', caller=alice)
        sim.call_public(cid, 'increment', caller=alice)
        block_result = sim.new_block()
        assert len(block_result.tx_results) == 2

        # Switch back to auto
        sim.auto_new_block = True
        sim.call_public(cid, 'increment', caller=alice)

        assert sim.call_view(cid, 'get_count') == 3
