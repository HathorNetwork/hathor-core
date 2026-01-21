# Copyright 2021 Hathor Labs
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

import re
from typing import Any, Optional, TypeVar, Union, cast

from twisted.web.http import Request
from twisted.web.resource import Resource as TwistedResource

from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import json_dumpb

T = TypeVar('T')


def set_cors(request: Request, method: str) -> None:
    request.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000')
    request.setHeader('Access-Control-Allow-Methods', method)
    request.setHeader('Access-Control-Allow-Headers', 'x-prototype-version,x-requested-with,content-type')
    request.setHeader('Access-Control-Max-Age', '604800')


def render_options(request: Request, verbs: str = 'GET, POST, OPTIONS') -> int:
    """Function to return OPTIONS request.

    Most of the APIs only need it for GET, POST and OPTIONS, but verbs can be passed as parameter.

    :param verbs: verbs to reply on render options
    :type verbs: str
    """
    from twisted.web import server
    set_cors(request, verbs)
    request.setHeader(b'content-type', b'application/json; charset=utf-8')
    request.write(b'')
    request.finish()
    return server.NOT_DONE_YET


def get_missing_params_msg(param_name):
    """Util function to return error response when a parameter is missing

    :param param_name: the missing parameter
    :type param_name: str
    """
    return json_dumpb({'success': False, 'message': f'Missing parameter: {param_name}'})


def parse_args(args: dict[bytes, list[bytes]], expected_args: list[str]) -> dict[str, Any]:
    """Parse all expected arguments. If there are missing arguments, returns the missing arguments
    """
    expected_set = set(expected_args)
    args_set = set()
    for arg1 in args:
        args_set.add(arg1.decode('utf-8'))

    # if there are expected args missing, we return None
    diff = expected_set.difference(args_set)
    if diff:
        return {'success': False, 'missing': ', '.join(sorted(diff))}

    ret: dict[str, str] = dict()
    for arg2 in expected_args:
        key_str = arg2.encode('utf-8')
        first_param = args[key_str][0]
        assert isinstance(first_param, bytes)
        ret[arg2] = first_param.decode('utf-8')

    return {'success': True, 'args': ret}


def parse_int(raw: Union[str, bytes], *,
              cap: Optional[int] = None, accept_negative: bool = False, accept_zero: bool = True) -> int:
    """Parse int, by default rejecting negative values."""
    value = int(raw)
    if not accept_zero and value == 0:
        raise ValueError('zero not accepted')
    if not accept_negative and value < 0:
        raise ValueError('negative value not accepted')
    if cap is not None:
        return min(value, cap)
    return value


def validate_tx_hash(hash_hex: str, tx_storage: TransactionStorage) -> tuple[bool, str]:
    """ Validate if the tx hash is valid and if it exists
        Return success and a message in case of failure
    """
    success = True
    message = ''
    pattern = r'[a-fA-F\d]{64}'
    # Check if parameter is a valid hex hash
    if not re.match(pattern, hash_hex):
        success = False
        message = 'Invalid hash'
    else:
        try:
            tx_storage.get_transaction(bytes.fromhex(hash_hex))
        except ValueError:
            success = False
            message = 'Invalid hash format'
        except TransactionDoesNotExist:
            success = False
            message = 'Transaction not found'

    return success, message


class Resource(TwistedResource):
    openapi: dict[str, Any] = {}


def get_args(request: Request) -> dict[bytes, list[bytes]]:
    """Type-friendly way to access request.args, also always returns a dict instead of None."""
    args = cast(Optional[dict[bytes, list[bytes]]], request.args)
    if args is None:
        return {}
    return args


def get_arg_default(args: dict[bytes, list[bytes]], key: str, default: T) -> T:
    """Get a value with given key from an request.args formatted dict, return default if key was not found.

    Examples:

    >>> args = {b'foo': [b'10'], b'bar': [b'abc']}
    >>> get_arg_default(args, 'foo', 4)
    10
    >>> get_arg_default(args, 'foo', '4')
    '10'
    >>> get_arg_default(args, 'bar', 4)
    Traceback (most recent call last):
     ...
    ValueError: invalid literal for int() with base 10: b'abc'
    >>> get_arg_default(args, 'bar', 'xyz')
    'abc'
    >>> get_arg_default(args, 'baz', 'xyz')
    'xyz'
    """
    assert isinstance(default, (type(None), str, int))
    bkey = key.encode()
    values = args.get(bkey)
    if not values:
        return default
    value: bytes = values[0]
    if isinstance(default, int):
        return cast(T, int(value))
    else:
        return cast(T, value.decode())
