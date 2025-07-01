#  Copyright 2025 Hathor Labs
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

import pytest

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.method import ArgsOnly
from hathor.nanocontracts.nc_failure import (
    BlueprintDoesNotExist,
    NCFailureException,
    NCMethodNotFound,
    NCUninitializedContractError,
)
from hathor.nanocontracts.runner.types import NCRawArgs
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context, a: int) -> None:
        pass


class TestExecutionVerification(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self.gen_random_blueprint_id()
        self.contract_id = self.gen_random_contract_id()
        self.register_blueprint_class(self.blueprint_id, MyBlueprint)

    def test_blueprint_does_not_exist(self) -> None:
        with pytest.raises(NCFailureException) as e:
            self.runner.create_contract(self.contract_id, self.gen_random_blueprint_id(), self.create_context(), 123)
        assert isinstance(e.value.get_inner(), BlueprintDoesNotExist)

    def test_contract_does_not_exist(self) -> None:
        with pytest.raises(NCFailureException) as e:
            self.runner.call_public_method(self.gen_random_contract_id(), 'method', self.create_context())
        assert isinstance(e.value.get_inner(), NCUninitializedContractError)

    def test_method_not_found(self) -> None:
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 123)

        with pytest.raises(NCFailureException) as e:
            self.runner.call_public_method(self.contract_id, 'not_found', self.create_context())
        assert isinstance(e.value.get_inner(), NCMethodNotFound)

    def test_empty_args(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == "MyBlueprint.initialize() missing 1 required positional argument: 'a'"

    def test_too_many_args(self) -> None:
        with pytest.raises(NCFail) as e:
            self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 123, 456)
        assert isinstance(e.value.__cause__, TypeError)
        assert e.value.__cause__.args[0] == "MyBlueprint.initialize() takes 3 positional arguments but 4 were given"

    @pytest.mark.xfail(strict=True, reason='not implemented yet')
    def test_wrong_arg_type_parsed(self) -> None:
        with pytest.raises(NCFail):
            self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context(), 'abc')

    def test_wrong_arg_type_raw(self) -> None:
        args_parser = ArgsOnly.from_arg_types((str,))
        args_bytes = args_parser.serialize_args_bytes(('abc',))
        nc_args = NCRawArgs(args_bytes)

        with pytest.raises(NCFail) as e:
            self.runner.create_contract_with_nc_args(
                self.contract_id, self.blueprint_id, self.create_context(), nc_args
            )
        assert isinstance(e.value.__cause__, ValueError)
        assert e.value.__cause__.args[0] == 'trailing data'

    @pytest.mark.xfail(strict=True, reason='not implemented yet')
    def test_wrong_arg_type_but_valid_serialization(self) -> None:
        args_parser = ArgsOnly.from_arg_types((str,))
        args_bytes = args_parser.serialize_args_bytes(('',))
        nc_args = NCRawArgs(args_bytes)

        with pytest.raises(NCFail):
            self.runner.create_contract_with_nc_args(
                self.contract_id, self.blueprint_id, self.create_context(), nc_args
            )
