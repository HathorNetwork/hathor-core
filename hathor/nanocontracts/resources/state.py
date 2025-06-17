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

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from pydantic import Field

from hathor.api_util import Resource
from hathor.cli.openapi_files.register import register_resource
from hathor.crypto.util import decode_address
from hathor.utils.api import QueryParams, Response
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

    def __init__(self, manager: 'HathorManager') -> None:
        super().__init__()
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        raise NotImplementedError('temporarily removed during nano merge')

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
        elif field.startswith("b'") and field.endswith("'"):
            # This field is bytes and we receive this in hexa
            hexa = field[2:-1]
            # This will raise ValueError in case it's an invalid hexa
            # and this will be handled in the get_key_for_field method
            return str(bytes.fromhex(hexa))
        return field


class NCStateParams(QueryParams):
    id: str
    fields: list[str] = Field(alias='fields[]', default_factory=list)
    balances: list[str] = Field(alias='balances[]', default_factory=list)
    calls: list[str] = Field(alias='calls[]', default_factory=list)
    block_hash: Optional[str]
    block_height: Optional[int]


class NCValueSuccessResponse(Response):
    value: Any


class NCBalanceSuccessResponse(Response):
    value: str
    can_mint: bool
    can_melt: bool


class NCValueErrorResponse(Response):
    errmsg: str


class NCStateResponse(Response):
    success: bool
    nc_id: str
    blueprint_id: str
    blueprint_name: str
    fields: dict[str, NCValueSuccessResponse | NCValueErrorResponse]
    balances: dict[str, NCBalanceSuccessResponse | NCValueErrorResponse]
    calls: dict[str, NCValueSuccessResponse | NCValueErrorResponse]


_openapi_success_value = {
    'success': True,
    'nc_id': '00007f246f6d645ef3174f2eddf53f4b6bd41e8be0c0b7fbea9827cf53e12d9e',
    'blueprint_id': '3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595',
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
                            'value': ['view_method_1(arg1, arg2)', 'view_method_2()']
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
                {
                    'name': 'block_height',
                    'in': 'query',
                    'description': 'Height of the block to get the nano contract state from.'
                                   'Can\'t be used together with block_hash parameter.',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'block_hash',
                    'in': 'query',
                    'description': 'Hash of the block to get the nano contract state from.'
                                   'Can\'t be used together with block_height parameter.',
                    'required': False,
                    'schema': {
                        'type': 'string'
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
