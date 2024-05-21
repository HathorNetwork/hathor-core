# Copyright 2022 Hathor Labs
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

import builtins
import inspect
import types
import typing
from typing import TYPE_CHECKING, Any, Optional, Type, get_args, get_origin

from hathor.api_util import Resource, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.nanocontracts import types as nc_types
from hathor.nanocontracts.exception import BlueprintDoesNotExist
from hathor.nanocontracts.types import Context
from hathor.utils.api import ErrorResponse, QueryParams, Response

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


@register_resource
class BlueprintInfoResource(Resource):
    """Implements a GET API to return information about a blueprint."""
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def _get_composed_type_name(self, type_name: str, args: tuple[Any, ...]) -> str:
        subtypes = ', '.join([self.get_type_name(x) for x in args])
        return f'{type_name}[{subtypes}]'

    def _get_optional_type_name(self, arg: Any) -> str:
        subtype = self.get_type_name(arg)
        return f'{subtype}?'

    def get_type_name(self, _type: Type[Any]) -> str:
        """Return a string representation for `_type`."""
        origin = get_origin(_type)
        args = get_args(_type)

        if (_type is type(None)) or (_type is None):  # noqa: E721
            return 'null'

        match origin:
            case builtins.dict | builtins.tuple | builtins.list | builtins.set:
                return self._get_composed_type_name(origin.__name__, args)
            case typing.Union | types.UnionType:
                match args:
                    case (_subtype, types.NoneType) | (types.NoneType, _subtype):
                        return self._get_optional_type_name(_subtype)
                return self._get_composed_type_name('union', args)
            case nc_types.SignedData:
                return self._get_composed_type_name('SignedData', args)

        return _type.__name__

    def render_GET(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = BlueprintInfoParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        try:
            blueprint_id_bytes = bytes.fromhex(params.blueprint_id)
        except ValueError:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error=f'Invalid id: {params.blueprint_id}')
            return error_response.json_dumpb()

        assert self.manager.tx_storage.nc_catalog is not None

        try:
            blueprint_class = self.manager.tx_storage.nc_catalog.get_blueprint_class(blueprint_id_bytes)
        except BlueprintDoesNotExist:
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error=f'Blueprint not found: {params.blueprint_id}')
            return error_response.json_dumpb()

        attributes: dict[str, str] = {}
        for name, _type in blueprint_class._fields.items():  # type: ignore
            assert name not in attributes
            attributes[name] = self.get_type_name(_type)

        public_methods = {}
        private_methods = {}
        skip_methods = {'__init__'}
        for name, method in inspect.getmembers(blueprint_class, predicate=inspect.isfunction):
            if name in skip_methods:
                continue

            method_args = []
            argspec = inspect.getfullargspec(method)
            for arg_name in argspec.args[1:]:
                arg_type = argspec.annotations[arg_name]
                if arg_type is Context:
                    continue
                method_args.append(MethodArgInfo(
                    name=arg_name,
                    type=self.get_type_name(arg_type),
                ))

            return_type = argspec.annotations.get('return', None)

            method_info = MethodInfo(
                args=method_args,
                return_type=self.get_type_name(return_type),
            )

            is_public = getattr(method, '_is_nc_public', False)
            if is_public:
                assert name not in public_methods
                public_methods[name] = method_info
            else:
                assert name not in private_methods
                private_methods[name] = method_info

        response = BlueprintInfoResponse(
            id=params.blueprint_id,
            name=blueprint_class.__name__,
            attributes=attributes,
            public_methods=public_methods,
            private_methods=private_methods,
        )
        return response.json_dumpb()


class BlueprintInfoParams(QueryParams):
    blueprint_id: str


class MethodArgInfo(Response):
    name: str
    type: str


class MethodInfo(Response):
    args: list[MethodArgInfo]
    return_type: Optional[str]


class BlueprintInfoResponse(Response):
    id: str
    name: str
    attributes: dict[str, str]
    public_methods: dict[str, MethodInfo]
    private_methods: dict[str, MethodInfo]


BlueprintInfoResource.openapi = {
    '/nano_contract/blueprint/info': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '100r/s',
                    'burst': 100,
                    'delay': 100
                }
            ],
            'per-ip': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'operationId': 'blueprint-info',
            'summary': 'Return information about a blueprint',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'id': '3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595',
                                        'name': 'Bet',
                                        'attributes': {
                                            'total_bets': 'int',
                                        },
                                        'public_methods': {
                                            'initialize': {
                                                'args': [{
                                                    'name': 'oracle_script',
                                                    'type': 'bytes'
                                                }],
                                                'return_type': 'null'
                                            },
                                            'bet': {
                                                'args': [{
                                                    'name': 'address',
                                                    'type': 'bytes',
                                                }, {
                                                    'name': 'score',
                                                    'type': 'str'
                                                }],
                                                'return_type': 'null'
                                            },
                                        },
                                        'private_methods': {
                                            'get_winner_amount': {
                                                'args': [{
                                                    'name': 'address',
                                                    'type': 'bytes'
                                                }],
                                                'return_type': 'int'
                                            },
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
