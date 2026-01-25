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

import re

import pytest

from hathor.nanocontracts import Blueprint, Context, public, view
from hathor.nanocontracts.exception import BlueprintSyntaxError
from hathor.nanocontracts.types import Address, NCArgs, fallback
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class TestBlueprintSyntax(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self.gen_random_blueprint_id()
        self.contract_id = self.gen_random_contract_id()
        self.ctx = self.create_context(
            actions=[],
            vertex=self.get_genesis_tx(),
            caller_id=Address(self.gen_random_address()),
            timestamp=self.now,
        )

    def test_success(self) -> None:
        class MyBlueprint(Blueprint):
            a: str

            @public
            def initialize(self, ctx: Context, a: int) -> int:
                self.a = ''
                return a

            @view
            def some_view(self, a: int) -> int:
                return a

            @fallback
            def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> int:
                return 123

        self.nc_catalog.blueprints[self.blueprint_id] = MyBlueprint
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.ctx, 123)

    def test_forbidden_field_name(self) -> None:
        with pytest.raises(BlueprintSyntaxError, match='field name is forbidden: `log`'):
            class MyBlueprint(Blueprint):
                log: str  # type: ignore

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_field_name_with_underscore(self) -> None:
        with pytest.raises(BlueprintSyntaxError, match='field name cannot start with underscore: `_a`'):
            class MyBlueprint(Blueprint):
                _a: str

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_field_with_default(self) -> None:
        with pytest.raises(BlueprintSyntaxError, match='fields with default values are currently not supported: `a`'):
            class MyBlueprint(Blueprint):
                a: str = 'a'

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_no_initialize(self) -> None:
        with pytest.raises(BlueprintSyntaxError, match='blueprints require a method called `initialize`'):
            class MyBlueprint(Blueprint):
                pass

    def test_initialize_non_public(self) -> None:
        with pytest.raises(BlueprintSyntaxError, match='`initialize` method must be annotated with @public'):
            class MyBlueprint(Blueprint):
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_initialize_view(self) -> None:
        with pytest.raises(BlueprintSyntaxError, match='`initialize` method cannot be annotated with @view'):
            class MyBlueprint(Blueprint):
                @view
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_initialize_fallback(self) -> None:
        msg = '@fallback method must be called `fallback`: `initialize()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @fallback
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_public_missing_self(self) -> None:
        msg = '@public method must have `self` argument: `initialize()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize() -> None:
                    pass

    def test_public_wrong_self(self) -> None:
        msg = '@public method first argument must be called `self`: `initialize()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(wrong) -> None:
                    pass

    def test_public_typed_self(self) -> None:
        msg = '@public method `self` argument must not be typed: `initialize()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self: int) -> None:
                    pass

    def test_view_missing_self(self) -> None:
        msg = '@view method must have `self` argument: `nop()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop() -> None:
                    pass

    def test_view_wrong_self(self) -> None:
        msg = '@view method first argument must be called `self`: `nop()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(wrong) -> None:
                    pass

    def test_view_typed_self(self) -> None:
        msg = '@view method `self` argument must not be typed: `nop()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(self: int) -> None:
                    pass

    def test_fallback_missing_self(self) -> None:
        msg = '@fallback method must have `self` argument: `fallback()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback() -> None:
                    pass

    def test_fallback_wrong_self(self) -> None:
        msg = '@fallback method first argument must be called `self`: `fallback()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(wrong) -> None:
                    pass

    def test_fallback_typed_self(self) -> None:
        msg = '@fallback method `self` argument must not be typed: `fallback()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self: int) -> None:
                    pass

    def test_public_missing_context(self) -> None:
        msg = '@public method must have `Context` argument: `initialize()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self) -> None:
                    pass

    def test_public_context_different_name_success(self) -> None:
        class MyBlueprint(Blueprint):
            @public
            def initialize(self, context: Context) -> None:
                pass

        self.nc_catalog.blueprints[self.blueprint_id] = MyBlueprint
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.ctx)

    def test_public_context_untyped(self) -> None:
        msg = 'argument `ctx` on method `initialize` must be typed'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx) -> None:  # type: ignore
                    pass

    def test_public_context_wrong_type(self) -> None:
        msg = '@public method second arg `ctx` argument must be of type `Context`: `initialize()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: int) -> None:
                    pass

    def test_fallback_missing_context(self) -> None:
        msg = '@fallback method must have `Context` argument: `fallback()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self) -> None:
                    pass

    def test_fallback_context_untyped(self) -> None:
        msg = 'argument `ctx` on method `fallback` must be typed'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx) -> None:  # type: ignore
                    pass

    def test_fallback_context_wrong_type(self) -> None:
        msg = '@fallback method second arg `ctx` argument must be of type `Context`: `fallback()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: int) -> None:
                    pass

    def test_view_with_ctx(self) -> None:
        msg = '@view method cannot have arg with type `Context`: `nop()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(self, ctx: Context) -> None:
                    pass

    def test_view_with_context_type(self) -> None:
        msg = '@view method cannot have arg with type `Context`: `nop()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(self, a: int, b: Context) -> None:
                    pass

    def test_cannot_have_multiple_method_types1(self) -> None:
        msg = 'method must be annotated with at most one method type: `nop()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @public
                @view
                def nop(self) -> None:
                    pass

    def test_cannot_have_multiple_method_types2(self) -> None:
        msg = 'method must be annotated with at most one method type: `nop()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                @view
                def nop(self) -> None:
                    pass

    def test_invalid_field_type(self) -> None:
        msg = 'unsupported field type: `a: float`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                a: float

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

    def test_public_missing_arg_type(self) -> None:
        msg = 'argument `a` on method `initialize` must be typed'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context, a) -> None:  # type: ignore
                    pass

    def test_public_invalid_arg_type(self) -> None:
        msg = 'unsupported type `float` on argument `a` of method `initialize`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context, a: float) -> None:
                    pass

    def test_public_missing_return_type(self) -> None:
        msg = 'missing return type on method `initialize`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context):  # type: ignore
                    pass

    def test_public_invalid_return_type(self) -> None:
        msg = 'unsupported return type `float` on method `initialize`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> float:
                    return 0

    def test_view_missing_arg_type(self) -> None:
        msg = 'argument `a` on method `nop` must be typed'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(self, a) -> None:  # type: ignore
                    pass

    def test_view_invalid_arg_type(self) -> None:
        msg = 'unsupported type `float` on argument `a` of method `nop`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(self, a: float) -> None:
                    pass

    def test_view_missing_return_type(self) -> None:
        msg = 'missing return type on method `nop`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(self):
                    pass

    def test_view_invalid_return_type(self) -> None:
        msg = 'unsupported return type `float` on method `nop`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def nop(self) -> float:
                    return 0

    def test_fallback_missing_args1(self) -> None:
        msg = '@fallback method must have these args: `ctx: Context, method_name: str, nc_args: NCArgs`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context) -> None:
                    pass

    def test_fallback_missing_args2(self) -> None:
        msg = '@fallback method must have these args: `ctx: Context, method_name: str, nc_args: NCArgs`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context, method_name: str) -> None:
                    pass

    def test_fallback_missing_arg_type1(self) -> None:
        msg = 'argument `method_name` on method `fallback` must be typed'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context, method_name, args_bytes: bytes) -> None:  # type: ignore
                    pass

    def test_fallback_missing_arg_type2(self) -> None:
        msg = 'argument `args_bytes` on method `fallback` must be typed'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context, method_name: str, args_bytes) -> None:  # type: ignore
                    pass

    def test_fallback_wrong_arg_type1(self) -> None:
        msg = '@fallback method must have these args: `ctx: Context, method_name: str, nc_args: NCArgs`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context, method_name: int, args_bytes: bytes) -> None:
                    pass

    def test_fallback_wrong_arg_type2(self) -> None:
        msg = '@fallback method must have these args: `ctx: Context, method_name: str, nc_args: NCArgs`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context, method_name: str, args_bytes: int) -> None:
                    pass

    def test_fallback_missing_return_type(self) -> None:
        msg = 'missing return type on method `fallback`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs):  # type: ignore
                    pass

    def test_fallback_invalid_return_type(self) -> None:
        msg = 'unsupported return type `float` on method `fallback`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> float:
                    return 0

    def test_fallback_wrong_name(self) -> None:
        msg = '@fallback method must be called `fallback`: `wrong()`'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @fallback
                def wrong(self) -> None:
                    pass

    def test_fallback_not_annotated(self) -> None:
        msg = '`fallback` method must be annotated with @fallback'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                def fallback(self) -> None:
                    pass

    def test_fallback_view(self) -> None:
        msg = '`fallback` method cannot be annotated with @view'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @view
                def fallback(self) -> None:
                    pass

    def test_fallback_public(self) -> None:
        msg = '`fallback` method cannot be annotated with @public'
        with pytest.raises(BlueprintSyntaxError, match=re.escape(msg)):
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    pass

                @public
                def fallback(self) -> None:
                    pass
