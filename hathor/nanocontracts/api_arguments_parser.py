# Copyright 2023 Hathor Labs
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

import json
from typing import Any

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import NCMethodNotFound
from hathor.nanocontracts.method import Method


def parse_nc_method_call(blueprint_class: type[Blueprint], call_info: str) -> tuple[str, Any, Method]:
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
    method = Method.from_callable(method_callable)
    parsed_args = method.args.json_to_value(args_json)

    return method_name, parsed_args, method
