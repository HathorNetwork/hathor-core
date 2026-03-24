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

from __future__ import annotations

import inspect
from typing import Callable

from hathorlib.nanocontracts.exception import BlueprintSyntaxError


def validate_has_self_arg(fn: Callable, annotation_name: str) -> None:
    """Validate the `self` arg of a callable."""
    arg_spec = inspect.getfullargspec(fn)
    if len(arg_spec.args) == 0:
        raise BlueprintSyntaxError(f'@{annotation_name} method must have `self` argument: `{fn.__name__}()`')

    if arg_spec.args[0] != 'self':
        raise BlueprintSyntaxError(
            f'@{annotation_name} method first argument must be called `self`: `{fn.__name__}()`'
        )

    if 'self' in arg_spec.annotations.keys():
        raise BlueprintSyntaxError(f'@{annotation_name} method `self` argument must not be typed: `{fn.__name__}()`')


def validate_method_types(fn: Callable) -> None:
    """Validate the arg and return types of a callable."""
    special_args = ['self']
    arg_spec = inspect.getfullargspec(fn)

    if 'return' not in arg_spec.annotations:
        raise BlueprintSyntaxError(f'missing return type on method `{fn.__name__}`')

    # TODO: This currently fails for types such as unions, probably because this is the wrong
    #  parsing function to use. Fix this.
    # from hathorlib.nanocontracts.fields import get_field_class_for_attr
    # return_type = arg_spec.annotations['return']
    # if return_type is not None:
    #     try:
    #         get_field_class_for_attr(return_type)
    #     except UnknownFieldType:
    #         raise BlueprintSyntaxError(
    #             f'unsupported return type `{return_type}` on method `{fn.__name__}`'
    #         )

    for arg_name in arg_spec.args:
        if arg_name in special_args:
            continue

        if arg_name not in arg_spec.annotations:
            raise BlueprintSyntaxError(f'argument `{arg_name}` on method `{fn.__name__}` must be typed')

        # TODO: This currently fails for @view methods with NamedTuple as args for example,
        #  because API calls use a different parsing function. Fix this.
        # arg_type = arg_spec.annotations[arg_name]
        # try:
        #     from hathorlib.nanocontracts.fields import get_field_class_for_attr
        #     get_field_class_for_attr(arg_type)
        # except UnknownFieldType:
        #     raise BlueprintSyntaxError(
        #         f'unsupported type `{arg_type.__name__}` on argument `{arg_name}` of method `{fn.__name__}`'
        #     )


def validate_has_ctx_arg(fn: Callable, annotation_name: str) -> None:
    """Validate the context arg of a callable."""
    arg_spec = inspect.getfullargspec(fn)

    if len(arg_spec.args) < 2:
        raise BlueprintSyntaxError(
            f'@{annotation_name} method must have `Context` argument: `{fn.__name__}()`'
        )

    from hathorlib.nanocontracts.context import Context
    second_arg = arg_spec.args[1]
    if arg_spec.annotations[second_arg] is not Context:
        raise BlueprintSyntaxError(
            f'@{annotation_name} method second arg `{second_arg}` argument must be of type `Context`: '
            f'`{fn.__name__}()`'
        )


def validate_has_not_ctx_arg(fn: Callable, annotation_name: str) -> None:
    """Validate that a callable doesn't have a `Context` arg."""
    from hathorlib.nanocontracts.context import Context
    arg_spec = inspect.getfullargspec(fn)
    if Context in arg_spec.annotations.values():
        raise BlueprintSyntaxError(f'@{annotation_name} method cannot have arg with type `Context`: `{fn.__name__}()`')
