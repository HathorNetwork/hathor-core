# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import re

import pytest

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import (
    BlueprintDoesNotExist,
    NCFail,
    NCMethodNotFound,
    NCUninitializedContractError,
)
from hathor.nanocontracts.method import ArgsOnly
from hathor.nanocontracts.types import NCRawArgs
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathorlib.token_amount_version import TokenAmountVersion


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context, a: int) -> None:
        pass


class TestExecutionVerification(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id = self.gen_random_contract_id()

    def test_successful_create_keeps_changes_pending_until_explicit_commit(self) -> None:
        runner = self.runner._runner

        assert not runner.has_pending_changes()
        assert not runner.block_storage.has_contract(self.contract_id)

        runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 123)

        assert runner.has_pending_changes()
        assert not runner.block_storage.has_contract(self.contract_id)

        runner.commit_pending_changes()

        assert not runner.has_pending_changes()
        assert runner.block_storage.has_contract(self.contract_id)

    def test_successful_create_can_be_explicitly_discarded(self) -> None:
        runner = self.runner._runner

        runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 123)

        assert runner.has_pending_changes()
        assert not runner.block_storage.has_contract(self.contract_id)

        runner.discard_pending_changes()

        assert not runner.has_pending_changes()
        assert not runner.has_contract_been_initialized(self.contract_id)
        assert not runner.block_storage.has_contract(self.contract_id)

    def test_blueprint_does_not_exist(self) -> None:
        with pytest.raises(BlueprintDoesNotExist):
            self.runner.create_contract(self.contract_id, self.gen_random_blueprint_id(), self.create_context(), 123)

    def test_contract_does_not_exist(self) -> None:
        with pytest.raises(NCUninitializedContractError):
            self.runner.call_public_method(self.gen_random_contract_id(), 'method', self.create_context())

    def test_method_not_found(self) -> None:
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 123)

        with pytest.raises(NCMethodNotFound):
            self.runner.call_public_method(self.contract_id, 'not_found', self.create_context())

    def test_empty_args(self) -> None:
        with pytest.raises(NCFail, match=re.escape("initialize() missing required argument: 'a'")):
            self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

    def test_too_many_args(self) -> None:
        with pytest.raises(NCFail, match='too many arguments'):
            self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 123, 456)

    def test_wrong_arg_type_parsed(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 'abc')
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == 'expected integer'

    def test_wrong_arg_type_raw(self) -> None:
        args_parser = ArgsOnly.from_arg_types((str,), TokenAmountVersion.V1)
        args_bytes = args_parser.serialize_args_bytes(('abc',))
        nc_args = NCRawArgs(args_bytes)

        with pytest.raises(NCFail) as e:
            self.runner.create_contract_with_nc_args(
                self.contract_id, self.blueprint_id, self.create_context(), nc_args
            )
        assert isinstance(e.value.__cause__, ValueError)
        assert e.value.__cause__.args[0] == 'trailing data'

    def test_failed_create_does_not_leave_contract_initialized(self) -> None:
        runner = self.runner._runner

        with pytest.raises(NCFail, match=re.escape("initialize() missing required argument: 'a'")):
            runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

        assert not runner.has_pending_changes()
        assert not runner.has_contract_been_initialized(self.contract_id)

        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 123)
        assert self.runner.has_contract_been_initialized(self.contract_id)

    @pytest.mark.xfail(strict=True, reason='not implemented yet')
    def test_wrong_arg_type_but_valid_serialization(self) -> None:
        args_parser = ArgsOnly.from_arg_types((str,), TokenAmountVersion.V1)
        args_bytes = args_parser.serialize_args_bytes(('',))
        nc_args = NCRawArgs(args_bytes)

        with pytest.raises(NCFail):
            self.runner.create_contract_with_nc_args(
                self.contract_id, self.blueprint_id, self.create_context(), nc_args
            )
