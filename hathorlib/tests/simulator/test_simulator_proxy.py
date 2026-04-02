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

"""Tests for ContractProxy — object-oriented contract interaction."""

import logging

import pytest

import hathorlib.nanocontracts.types as _nc_types
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.types import NC_HTR_TOKEN_UID, SignedData, TxOutputScript
from hathorlib.simulator import CHECKSIG_INVALID, CHECKSIG_VALID, ContractProxy, SimulatorBuilder, TxResult

from .blueprints import CollectionArgs, Counter, FailingBlueprint, SignedMessage, Vault


class TestContractProxy:
    def test_proxy_public_method(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        counter = sim.create_instance(bid, caller=alice)
        assert sim.call_view(counter.contract_id, 'get_count') == 0

        result = counter.increment(caller=alice)
        assert isinstance(result, TxResult)
        assert sim.call_view(counter.contract_id, 'get_count') == 1

    def test_proxy_view_method(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        counter = sim.create_instance(bid, caller=alice)
        assert counter.get_count() == 0

        counter.increment(caller=alice)
        assert counter.get_count() == 1

    def test_proxy_public_with_args(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(FailingBlueprint)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice)
        assert proxy.get_value() == 42

        proxy.set_value(100, caller=alice)
        assert proxy.get_value() == 100

    def test_proxy_with_actions(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Vault)
        alice = sim.create_address('alice')

        vault = sim.create_instance(bid, caller=alice, actions=[sim.deposit(NC_HTR_TOKEN_UID, 1000)])
        assert vault.get_total() == 1000

        vault.deposit_more(caller=alice, actions=[sim.deposit(NC_HTR_TOKEN_UID, 500)])
        assert vault.get_total() == 1500

        vault.withdraw(300, caller=alice)
        assert vault.get_total() == 1200

    def test_proxy_has_contract_id(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        counter = sim.create_instance(bid, caller=alice)
        assert counter.contract_id is not None
        assert sim.has_contract(counter.contract_id)

    def test_proxy_has_tx_result(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        counter = sim.create_instance(bid, caller=alice)
        assert counter.tx_result is not None
        assert isinstance(counter.tx_result, TxResult)
        assert counter.tx_result.contract_id == counter.contract_id

    def test_wrap_existing_contract(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        result = sim.create_contract(bid, caller=alice)
        counter = sim.wrap(result.contract_id)

        assert isinstance(counter, ContractProxy)
        assert counter.contract_id == result.contract_id
        assert counter.tx_result is None

        assert counter.get_count() == 0
        counter.increment(caller=alice)
        assert counter.get_count() == 1

    def test_proxy_initialize_not_exposed(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(Counter)
        alice = sim.create_address('alice')

        counter = sim.create_instance(bid, caller=alice)
        assert not hasattr(counter, 'initialize')

    def test_proxy_failed_call_raises(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(FailingBlueprint)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice)

        proxy.set_value(100, caller=alice)
        assert proxy.get_value() == 100

        with pytest.raises(NCFail, match='intentional failure'):
            proxy.fail_method(0, caller=alice)

        # Value should still be 100 (failed call not committed)
        assert proxy.get_value() == 100


class TestProxyCollectionArgs:
    def test_proxy_list_arg(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(CollectionArgs)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice)
        assert proxy.get_total() == 0

        proxy.sum_list([10, 20, 30], caller=alice)
        assert proxy.get_total() == 60

    def test_proxy_dict_arg(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(CollectionArgs)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice)
        proxy.sum_dict_values({'a': 5, 'b': 15, 'c': 30}, caller=alice)
        assert proxy.get_total() == 50

    def test_proxy_set_arg(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(CollectionArgs)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice)
        proxy.count_unique({1, 2, 3, 3, 2}, caller=alice)
        assert proxy.get_total() == 3


class TestProxySignedData:
    ORACLE_SCRIPT = TxOutputScript(b'oracle-secret')

    def test_proxy_signed_data_valid(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(SignedMessage)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice, args=(self.ORACLE_SCRIPT,))
        assert proxy.get_message() == ''

        assert _nc_types._checksig_backend is None
        signed = SignedData[str]('hello world', CHECKSIG_VALID)
        proxy.set_message(signed, caller=alice)
        assert _nc_types._checksig_backend is None
        assert proxy.get_message() == 'hello world'

    def test_proxy_signed_data_invalid(self) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(SignedMessage)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice, args=(self.ORACLE_SCRIPT,))

        signed = SignedData[str]('hello world', CHECKSIG_INVALID)
        with pytest.raises(NCFail, match='invalid signature'):
            proxy.set_message(signed, caller=alice)

    def test_proxy_signed_data_unrecognized_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(SignedMessage)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice, args=(self.ORACLE_SCRIPT,))

        signed = SignedData[str]('hello world', b'some-random-bytes')
        with caplog.at_level(logging.WARNING):
            with pytest.raises(NCFail, match='invalid signature'):
                proxy.set_message(signed, caller=alice)

        assert 'Simulated checksig received unrecognized script_input' in caplog.text

    def test_checksig_disabled(self) -> None:
        sim = SimulatorBuilder().with_checksig(None).build()
        bid = sim.register_blueprint(SignedMessage)
        alice = sim.create_address('alice')

        proxy = sim.create_instance(bid, caller=alice, args=(self.ORACLE_SCRIPT,))

        # Without the simulated backend, checksig raises NotImplementedError
        # which the metered executor wraps in NCFail
        signed = SignedData[str]('hello world', CHECKSIG_VALID)
        with pytest.raises(NCFail):
            proxy.set_message(signed, caller=alice)
