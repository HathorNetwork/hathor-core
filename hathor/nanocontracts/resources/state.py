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

import json
from typing import TYPE_CHECKING, Any, Optional

from pydantic import Field

from hathor.api_util import Resource, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.crypto.util import decode_address
from hathor.nanocontracts.api_arguments_parser import parse_arg
from hathor.nanocontracts.exception import NCContractCreationNotFound, NCMethodNotFound
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.nanocontract import NanoContract
from hathor.nanocontracts.utils import get_nano_contract_creation
from hathor.utils.api import ErrorResponse, QueryParams, Response
from hathor.wallet.exceptions import InvalidAddress

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


@register_resource
class NanoContractStateResource(Resource):
    """ Implements a web server GET API to get a nano contract state.
    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = NCStateParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        try:
            nc_id_bytes = bytes.fromhex(params.id)
        except ValueError:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error=f'Invalid id: {params.id}')
            return error_response.json_dumpb()

        # Check if the contract exists.
        try:
            nanocontract = get_nano_contract_creation(self.manager.tx_storage, nc_id_bytes)
        except NCContractCreationNotFound:
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error=f'Nano contract not found: {params.id}')
            return error_response.json_dumpb()

        nc_storage = self.manager.consensus_algorithm.nc_storage_factory(nc_id_bytes)
        value: Any

        # Get balances.
        balances: dict[str, NCValueSuccessResponse | NCValueErrorResponse] = {}
        for token_uid_hex in params.balances:
            if token_uid_hex == '__all__':
                # User wants to get the balance of all tokens in the nano contract
                all_balances = nc_storage.get_all_balances()
                for key_balance, value in all_balances.items():
                    balances[key_balance.token_uid.hex()] = NCValueSuccessResponse(value=str(value))
                break

            try:
                token_uid = bytes.fromhex(token_uid_hex)
            except ValueError:
                balances[token_uid_hex] = NCValueErrorResponse(errmsg='invalid token id')
                continue

            value = nc_storage.get_balance(token_uid)
            balances[token_uid_hex] = NCValueSuccessResponse(value=str(value))

        # Get fields.
        fields: dict[str, NCValueSuccessResponse | NCValueErrorResponse] = {}
        param_fields: list[str] = params.fields
        for field in param_fields:
            key_field = self.get_key_for_field(field)
            if key_field is None:
                fields[field] = NCValueErrorResponse(errmsg='invalid format')
                continue

            try:
                value = nc_storage.get(key_field)
            except KeyError:
                fields[field] = NCValueErrorResponse(errmsg='field not found')
                continue

            if type(value) is bytes:
                value = value.hex()
            fields[field] = NCValueSuccessResponse(value=value)

        # Call private methods.
        calls: dict[str, NCValueSuccessResponse | NCValueErrorResponse] = {}
        for call_info in params.calls:
            try:
                method_name, method_args = self.parse_call_info(nanocontract, call_info)
                value = nanocontract.call_private_method(nc_storage, method_name, *method_args)
                if type(value) is bytes:
                    value = value.hex()
            except Exception as e:
                calls[call_info] = NCValueErrorResponse(errmsg=repr(e))
            else:
                calls[call_info] = NCValueSuccessResponse(value=value)

        response = NCStateResponse(
            success=True,
            nc_id=params.id,
            blueprint_name=nanocontract.get_blueprint_class().__name__,
            fields=fields,
            balances=balances,
            calls=calls,
        )
        return response.json_dumpb()

    def parse_call_info(self, nanocontract: NanoContract, call_info: str) -> tuple[str, list[Any]]:
        """Parse call_info string into (method_name, method_args).

        The expected string format is "method_name(arg1, arg2, arg3, ...)".
        """
        if not call_info.endswith(')'):
            raise ValueError
        method_name, _, arguments = call_info[:-1].partition('(')

        blueprint_class = nanocontract.get_blueprint_class()
        method = getattr(blueprint_class, method_name, None)
        if method is None:
            raise NCMethodNotFound

        parser = NCMethodParser(method)
        method_args = parser.get_method_args()

        args_array = json.loads(f'[{arguments}]')
        assert len(args_array) == len(method_args), f'{len(args_array)} != {len(method_args)} ({method_args})'

        parsed_args = []
        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        return method_name, parsed_args

    def get_key_for_field(self, field: str) -> Optional[str]:
        """Return the storage key for a given field."""
        # Queries might have multiple parts separated by '.'
        parts = field.split('.')
        try:
            key_parts = [self.parse_field_name(name) for name in parts]
        except ValueError:
            return None
        return ':'.join(key_parts)

    def parse_field_name(self, field: str) -> str:
        """Parse field names."""
        if field.startswith("a'") and field.endswith("'"):
            # Addresses are decoded to bytes
            address = field[2:-1]
            try:
                return str(decode_address(address))
            except InvalidAddress as e:
                raise ValueError from e
        return field


class NCStateParams(QueryParams):
    id: str
    fields: list[str] = Field(alias='fields[]', default=[])
    balances: list[str] = Field(alias='balances[]', default=[])
    calls: list[str] = Field(alias='calls[]', default=[])


class NCValueSuccessResponse(Response):
    value: Any


class NCValueErrorResponse(Response):
    errmsg: str


class NCStateResponse(Response):
    success: bool
    nc_id: str
    blueprint_name: str
    fields: dict[str, NCValueSuccessResponse | NCValueErrorResponse]
    balances: dict[str, NCValueSuccessResponse | NCValueErrorResponse]
    calls: dict[str, NCValueSuccessResponse | NCValueErrorResponse]


_openapi_success_value = {
    'success': True,
    'nc_id': '3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595',
    'blueprint_name': 'Bet',
    'fields': {
        'token_uid': {'value': '00'},
        'total': {'value': 300},
        'final_result': {'value': '1x0'},
        'oracle_script': {'value': '76a91441c431ff7ad5d6ce5565991e3dcd5d9106cfd1e288ac'},
        'withdrawals.a\'Wi8zvxdXHjaUVAoCJf52t3WovTZYcU9aX6\'': {'value': 300},
        'address_details.a\'Wi8zvxdXHjaUVAoCJf52t3WovTZYcU9aX6\'': {'value': {'1x0': 100}},
    }
}


NanoContractStateResource.openapi = {
    '/nano_contract/state': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '10r/s',
                    'burst': 20,
                    'delay': 10
                }
            ],
            'per-ip': [
                {
                    'rate': '2r/s',
                    'burst': 6,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['nano_contracts'],
            'operationId': 'nano_contracts_state',
            'summary': 'Get state of a nano contract',
            'description': 'Returns the state requested of a nano contract.',
            'parameters': [
                {
                    'name': 'id',
                    'in': 'query',
                    'description': 'ID of the nano contract to get the state from',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'balances[]',
                    'in': 'query',
                    'description': 'List of token ids in hex to get the contract balance. '
                                   'If you want to get the balance for all tokens in the contract, just use __all__.',
                    'required': False,
                    'schema': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        }
                    },
                    'examples': {
                        'balances': {
                            'summary': 'Example of balances',
                            'value': ['00', '000008f2ee2059a189322ae7cb1d7e7773dcb4fdc8c4de8767f63022b3731845']
                        },
                    }
                },
                {
                    'name': 'calls[]',
                    'in': 'query',
                    'description': 'List of private method calls to be executed. '
                                   'The format must be "method_name(arg1, arg2, arg3, ...)". '
                                   'Bytes arguments must be sent in hex, address arguments in bytes '
                                   'must be sent as hex itself, or in base58 with the address tag, e.g. '
                                   'a\'Wi8zvxdXHjaUVAoCJf52t3WovTZYcU9aX6\', and tuple arguments must be '
                                   'sent as an array, e.g., (a, b, c) must be sent as [a, b, c]. '
                                   'For SignedData field we expect a list with two elements, where the '
                                   'first one is the data to be signed and the second is the signature in hex.',
                    'required': False,
                    'schema': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        }
                    },
                    'examples': {
                        'calls': {
                            'summary': 'Example of calls',
                            'value': ['private_method_1(arg1, arg2)', 'private_method_2()']
                        },
                    }
                },
                {
                    'name': 'fields[]',
                    'in': 'query',
                    'description': 'Fields to get the data from the nano contract state',
                    'required': False,
                    'schema': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        }
                    },
                    'examples': {
                        'simple fields': {
                            'summary': 'Only direct fields',
                            'value': ['token_uid', 'total', 'final_result', 'oracle_script']
                        },
                        'With dict fields': {
                            'summary': ('Simple and dict fields (dict fields where the keys are addresses). '
                                        'For an address you must encapsulate the b58 with a\'\''),
                            'value': [
                                'token_uid',
                                'total',
                                'final_result',
                                'oracle_script',
                                'withdrawals.a\'Wi8zvxdXHjaUVAoCJf52t3WovTZYcU9aX6\'',
                                'address_details.a\'Wi8zvxdXHjaUVAoCJf52t3WovTZYcU9aX6\''
                            ]
                        },
                    }
                },
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success to get state from nano',
                                    'value': _openapi_success_value,
                                },
                                'error': {
                                    'summary': 'Invalid nano contract ID',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid nano contract ID.'
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}
