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

"""Token deposit/withdrawal tests."""

import pytest

from hathorlib.nanocontracts.exception import NCFail
from hathorlib.simulator import Simulator, SimulatorBuilder
from hathorlib.nanocontracts.types import NC_HTR_TOKEN_UID

from .blueprints import Vault


class TestSimulatorTokens:
    def test_deposit_on_initialize(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Vault)
        alice = sim.create_address('alice')

        result = sim.create_contract(
            bid,
            caller=alice,
            actions=[Simulator.deposit(NC_HTR_TOKEN_UID, 1000)],
        )
        assert sim.call_view(result.contract_id, 'get_total') == 1000

    def test_deposit_and_withdraw(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Vault)
        alice = sim.create_address('alice')

        result = sim.create_contract(
            bid,
            caller=alice,
            actions=[Simulator.deposit(NC_HTR_TOKEN_UID, 1000)],
        )
        cid = result.contract_id

        sim.call_public(
            cid, 'withdraw',
            caller=alice,
            args=(300,),
            actions=[Simulator.withdrawal(NC_HTR_TOKEN_UID, 300)],
        )
        assert sim.call_view(cid, 'get_total') == 700

    def test_multiple_deposits(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Vault)
        alice = sim.create_address('alice')

        result = sim.create_contract(
            bid,
            caller=alice,
            actions=[Simulator.deposit(NC_HTR_TOKEN_UID, 500)],
        )
        cid = result.contract_id

        sim.call_public(
            cid, 'deposit_more',
            caller=alice,
            actions=[Simulator.deposit(NC_HTR_TOKEN_UID, 300)],
        )
        assert sim.call_view(cid, 'get_total') == 800

    def test_withdraw_too_much_fails(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Vault)
        alice = sim.create_address('alice')

        result = sim.create_contract(
            bid,
            caller=alice,
            actions=[Simulator.deposit(NC_HTR_TOKEN_UID, 100)],
        )

        with pytest.raises(NCFail, match='Insufficient funds'):
            sim.call_public(
                result.contract_id, 'withdraw',
                caller=alice,
                args=(200,),
                actions=[Simulator.withdrawal(NC_HTR_TOKEN_UID, 200)],
            )

        # Balance unchanged
        assert sim.call_view(result.contract_id, 'get_total') == 100

    def test_create_custom_token(self) -> None:
        sim = SimulatorBuilder().build()
        token_uid = sim.create_token('TestToken', 'TST')
        assert token_uid is not None
        assert len(token_uid) == 32
