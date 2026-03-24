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

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.crypto.util import decode_address
from hathor.nanocontracts.api_arguments_parser import parse_nc_method_call
from hathor.nanocontracts.exception import NanoContractDoesNotExist
from hathor.nanocontracts.nc_types import make_nc_type_for_field_type
from hathor.nanocontracts.types import ContractId, VertexId
from hathor.utils.api import ErrorResponse, QueryParams, Response
from hathor.wallet.exceptions import InvalidAddress

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager
    from hathor.nanocontracts.storage import NCContractStorage
    from hathor.transaction import Block


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
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = NCStateParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        if sum(x is not None for x in (params.block_hash, params.block_height, params.timestamp)) > 1:
            request.setResponseCode(400)
            error_response = ErrorResponse(
                success=False,
                error='only one of `block_hash`, `block_height`, or `timestamp` must be used',
            )
            return error_response.json_dumpb()

        try:
            nc_id_bytes = ContractId(VertexId(bytes.fromhex(params.id)))
        except ValueError:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error=f'Invalid id: {params.id}')
            return error_response.json_dumpb()

        nc_storage: NCContractStorage
        block: Block
        block_hash: Optional[bytes]
        try:
            block_hash = bytes.fromhex(params.block_hash) if params.block_hash else None
        except ValueError:
            # This error will be raised in case the block_hash parameter is an invalid hex
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error=f'Invalid block_hash parameter: {params.block_hash}')
            return error_response.json_dumpb()

        if params.block_height is not None:
            # Get hash of the block with the height
            block_hash = self.manager.tx_storage.indexes.height.get(params.block_height)
            if block_hash is None:
                # No block hash was found with this height
                request.setResponseCode(400)
                error_response = ErrorResponse(
                                    success=False,
                                    error=f'No block hash was found with height {params.block_height}.'
                                )
                return error_response.json_dumpb()
        elif params.timestamp is not None:
            block_hashes, has_more = self.manager.tx_storage.indexes.sorted_blocks.get_older(
                timestamp=params.timestamp,
                hash_bytes=None,
                count=1,
            )
            if not block_hashes:
                # No block hash was found before this timestamp
                request.setResponseCode(400)
                error_response = ErrorResponse(
                    success=False,
                    error=f'No block hash was found before timestamp {params.timestamp}.'
                )
                return error_response.json_dumpb()
            assert len(block_hashes) == 1
            block_hash = block_hashes[0]

        if block_hash:
            try:
                block = self.manager.tx_storage.get_block(block_hash)
            except AssertionError:
                # This block hash is not from a block
                request.setResponseCode(400)
                error_response = ErrorResponse(success=False, error=f'Invalid block_hash {params.block_hash}.')
                return error_response.json_dumpb()
        else:
            block = self.manager.tx_storage.get_best_block()

        try:
            runner = self.manager.get_nc_runner(block)
            nc_storage = runner.get_storage(nc_id_bytes)
        except NanoContractDoesNotExist:
            # Nano contract does not exist at this block
            request.setResponseCode(404)
            error_response = ErrorResponse(
                success=False,
                error=f'Nano contract does not exist at block {block.hash_hex}.'
            )
            return error_response.json_dumpb()

        blueprint_id = nc_storage.get_blueprint_id()
        blueprint_class = self.manager.tx_storage.get_blueprint_class(blueprint_id)

        value: Any
        # Get balances.
        balances: dict[str, NCBalanceSuccessResponse | NCValueErrorResponse] = {}
        for token_uid_hex in params.balances:
            if token_uid_hex == '__all__':
                # User wants to get the balance of all tokens in the nano contract
                all_balances = nc_storage.get_all_balances()
                for key_balance, balance in all_balances.items():
                    balances[key_balance.token_uid.hex()] = NCBalanceSuccessResponse(
                        value=str(balance.value),
                        can_mint=balance.can_mint,
                        can_melt=balance.can_melt,
                    )
                break

            try:
                token_uid = bytes.fromhex(token_uid_hex)
            except ValueError:
                balances[token_uid_hex] = NCValueErrorResponse(errmsg='invalid token id')
                continue

            balance = nc_storage.get_balance(token_uid)
            balances[token_uid_hex] = NCBalanceSuccessResponse(
                value=str(balance.value),
                can_mint=balance.can_mint,
                can_melt=balance.can_melt,
            )

        # Get fields.
        fields: dict[str, NCValueSuccessResponse | NCValueErrorResponse] = {}
        param_fields: list[str] = params.fields
        for field in param_fields:
            key_field = self.get_key_for_field(field)
            if key_field is None:
                fields[field] = NCValueErrorResponse(errmsg='invalid format')
                continue

            try:
                field_type = blueprint_class.__annotations__[field]
            except KeyError:
                fields[field] = NCValueErrorResponse(errmsg='not a blueprint field')
                continue

            try:
                field_nc_type = make_nc_type_for_field_type(field_type)
                value = nc_storage.get_obj(key_field.encode(), field_nc_type)
            except KeyError:
                fields[field] = NCValueErrorResponse(errmsg='field not found')
                continue
            except TypeError:
                fields[field] = NCValueErrorResponse(errmsg='field cannot be rendered')
                continue

            json_value = field_nc_type.value_to_json(value)
            fields[field] = NCValueSuccessResponse(value=json_value)

        # Call view methods.
        runner.disable_call_trace()  # call trace is not required for calling view methods.
        calls: dict[str, NCValueSuccessResponse | NCValueErrorResponse] = {}
        for call_info in params.calls:
            try:
                method_name, method_args, method = parse_nc_method_call(blueprint_class, call_info)
                value = runner.call_view_method(nc_id_bytes, method_name, *method_args)
                value = method.return_.value_to_json(value)
            except Exception as e:
                calls[call_info] = NCValueErrorResponse(errmsg=repr(e))
            else:
                calls[call_info] = NCValueSuccessResponse(value=value)

        response = NCStateResponse(
            success=True,
            nc_id=params.id,
            blueprint_id=blueprint_id.hex(),
            blueprint_name=blueprint_class.__name__,
            fields=fields,
            balances=balances,
            calls=calls,
        )
        return response.json_dumpb()

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
    block_hash: Optional[str] = None
    block_height: Optional[int] = None
    timestamp: Optional[int] = None


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
                    'rate': '30r/s',
                    'burst': 20,
                    'delay': 10
                }
            ],
            'per-ip': [
                {
                    'rate': '5r/s',
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
                                   'Can\'t be used together with block_hash or timestamp parameter.',
                    'required': False,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'block_hash',
                    'in': 'query',
                    'description': 'Hash of the block to get the nano contract state from.'
                                   'Can\'t be used together with block_height or timestamp parameter.',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'timestamp',
                    'in': 'query',
                    'description': 'Timestamp to get the nano contract state from.'
                                   'Can\'t be used together with block_hash or block_height parameter.',
                    'required': False,
                    'schema': {
                        'type': 'int'
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
