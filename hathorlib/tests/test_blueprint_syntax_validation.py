# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# mypy: disable-error-code="no-untyped-def"


import unittest

from hathorlib.nanocontracts.blueprint_syntax_validation import (
    validate_has_ctx_arg,
    validate_has_not_ctx_arg,
    validate_has_self_arg,
    validate_method_types,
)
from hathorlib.nanocontracts.context import Context
from hathorlib.nanocontracts.exception import BlueprintSyntaxError


class TestValidateHasSelfArg(unittest.TestCase):
    def test_valid(self) -> None:
        def my_method(self, ctx: Context) -> None:
            pass
        # Should not raise
        validate_has_self_arg(my_method, 'public')

    def test_no_args(self) -> None:
        def my_method() -> None:
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_has_self_arg(my_method, 'public')

    def test_first_arg_not_self(self) -> None:
        def my_method(this: int) -> None:
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_has_self_arg(my_method, 'public')

    def test_self_typed(self) -> None:
        def my_method(self: int) -> None:
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_has_self_arg(my_method, 'public')


class TestValidateMethodTypes(unittest.TestCase):
    def test_valid(self) -> None:
        def my_method(self, ctx: Context) -> None:
            pass
        validate_method_types(my_method)

    def test_missing_return_type(self) -> None:
        def my_method(self, ctx: Context):
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_method_types(my_method)

    def test_untyped_arg(self) -> None:
        def my_method(self, ctx) -> None:
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_method_types(my_method)


class TestValidateHasCtxArg(unittest.TestCase):
    def test_valid(self) -> None:
        def my_method(self, ctx: Context) -> None:
            pass
        validate_has_ctx_arg(my_method, 'public')

    def test_no_second_arg(self) -> None:
        def my_method(self) -> None:
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_has_ctx_arg(my_method, 'public')

    def test_wrong_type(self) -> None:
        def my_method(self, ctx: int) -> None:
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_has_ctx_arg(my_method, 'public')


class TestValidateHasNotCtxArg(unittest.TestCase):
    def test_valid_no_context(self) -> None:
        def my_method(self, x: int) -> None:
            pass
        validate_has_not_ctx_arg(my_method, 'view')

    def test_has_context_raises(self) -> None:
        def my_method(self, ctx: Context) -> None:
            pass
        with self.assertRaises(BlueprintSyntaxError):
            validate_has_not_ctx_arg(my_method, 'view')
