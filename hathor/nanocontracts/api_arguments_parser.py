# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Any

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import NCMethodNotFound
from hathor.nanocontracts.method import Method
from hathorlib.token_amount_version import TokenAmountVersion


def parse_nc_method_call(
    blueprint_class: type[Blueprint],
    call_info: str,
    token_amount_version: TokenAmountVersion,
) -> tuple[str, Any, Method]:
    """Parse a string that represents an invocation to a Nano Contract method.

    The string must be in the following format: `method(arg1, arg2, arg3)`.

    The arguments must be in JSON format; tuples and namedtuples should be replaced by a list.

    Here are some examples:
    - add(1, 2)
    - set_result("1x2")
    """
    if not call_info.endswith(')'):
        raise ValueError

    method_name, _, arguments_raw = call_info[:-1].partition('(')
    method_callable = getattr(blueprint_class, method_name, None)
    if method_callable is None:
        raise NCMethodNotFound(f'{blueprint_class.__name__}.{method_name}')

    args_json = json.loads(f'[{arguments_raw}]')
    method = Method.from_callable(method_callable, token_amount_version)
    parsed_args = method.args.json_to_value(args_json)

    return method_name, parsed_args, method
