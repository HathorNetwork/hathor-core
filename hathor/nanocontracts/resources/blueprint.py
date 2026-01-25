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
from typing import TYPE_CHECKING, Any, Optional

import hathor
from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.nanocontracts import types as nc_types
from hathor.nanocontracts.blueprint import NC_FIELDS_ATTR
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import BlueprintDoesNotExist, OCBBlueprintNotConfirmed
from hathor.nanocontracts.types import blueprint_id_from_bytes
from hathor.nanocontracts.utils import is_nc_public_method, is_nc_view_method
from hathor.utils.api import ErrorResponse, QueryParams, Response
from hathor.utils.typing import get_args, get_origin

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

    def get_type_name(self, type_: type) -> str:
        """Return a string representation for `type_`."""
        origin = get_origin(type_) or type_
        args = get_args(type_) or tuple()

        if (type_ is type(None)) or (type_ is None):  # noqa: E721
            return 'null'

        match origin:
            case builtins.dict | builtins.tuple | builtins.list | builtins.set:
                return self._get_composed_type_name(origin.__name__, args)
            case typing.Union | types.UnionType:
                match args:
                    case (_subtype, types.NoneType) | (types.NoneType, _subtype):
                        return self._get_optional_type_name(_subtype)
                    case (hathor.Address, hathor.ContractId) | (hathor.ContractId, hathor.Address):
                        return 'CallerId'
                return self._get_composed_type_name('union', args)
            case nc_types.SignedData:
                return self._get_composed_type_name('SignedData', args)

        return type_.__name__

    def render_GET(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = BlueprintInfoParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        try:
            blueprint_id = blueprint_id_from_bytes(bytes.fromhex(params.blueprint_id))
        except ValueError:
            request.setResponseCode(400)
            error_response = ErrorResponse(success=False, error=f'Invalid id: {params.blueprint_id}')
            return error_response.json_dumpb()

        try:
            blueprint_class, _ = self.manager.tx_storage.get_blueprint_class(blueprint_id)
        except BlueprintDoesNotExist:
            request.setResponseCode(404)
            error_response = ErrorResponse(success=False, error=f'Blueprint not found: {params.blueprint_id}')
            return error_response.json_dumpb()
        except OCBBlueprintNotConfirmed:
            request.setResponseCode(404)
            error_response = ErrorResponse(
                success=False,
                error=f'Blueprint found but not confirmed: {params.blueprint_id}',
            )
            return error_response.json_dumpb()

        attributes: dict[str, str] = {}
        fields = getattr(blueprint_class, NC_FIELDS_ATTR)
        for name, _type in fields.items():
            assert name not in attributes
            attributes[name] = self.get_type_name(_type)

        public_methods = {}
        view_methods = {}
        skip_methods = {'__init__'}
        for name, method in inspect.getmembers(blueprint_class, predicate=inspect.isfunction):
            if name in skip_methods:
                continue

            if not (is_nc_public_method(method) or is_nc_view_method(method)):
                continue

            method_args = []
            signature = inspect.signature(method)
            for parameter in signature.parameters.values():
                if parameter.name == 'self':
                    continue
                arg_type = parameter.annotation
                if arg_type is Context:
                    continue
                method_args.append(MethodArgInfo(
                    name=parameter.name,
                    type=self.get_type_name(arg_type),
                ))

            return_type = signature.return_annotation
            if return_type is inspect._empty:  # allow-is
                return_type = None

            method_info = MethodInfo(
                args=method_args,
                return_type=self.get_type_name(return_type),
                docstring=inspect.getdoc(method),
            )

            if is_nc_public_method(method):
                assert name not in public_methods
                public_methods[name] = method_info

            if is_nc_view_method(method):
                assert name not in view_methods
                view_methods[name] = method_info

        response = BlueprintInfoResponse(
            id=params.blueprint_id,
            name=blueprint_class.__name__,
            attributes=attributes,
            public_methods=public_methods,
            private_methods=view_methods,  # DEPRECATED
            view_methods=view_methods,
            docstring=inspect.getdoc(blueprint_class),
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
    docstring: str | None


class BlueprintInfoResponse(Response):
    id: str
    name: str
    attributes: dict[str, str]
    public_methods: dict[str, MethodInfo]
    private_methods: dict[str, MethodInfo]  # DEPRECATED
    view_methods: dict[str, MethodInfo]
    docstring: str | None


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
                                        'view_methods': {
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
