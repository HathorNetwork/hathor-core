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

import base64
from typing import Literal, Union

from pydantic import Field

from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api.schemas import ResponseModel
from hathor.api_util import Resource, set_cors
from hathor.manager import HathorManager
from hathor.transaction.scripts import create_base_script
from hathor.util import api_catch_exceptions


class ValidateAddressSuccessResponse(ResponseModel):
    """Response model for valid address."""
    valid: Literal[True] = Field(description="Whether the address is valid")
    script: str = Field(description="Base64-encoded output script")
    address: str = Field(description="Base58-encoded address")
    type: str = Field(description="Address type (e.g., 'p2pkh', 'multisig')")


class ValidateAddressErrorResponse(ResponseModel):
    """Response model for invalid address."""
    valid: Literal[False] = Field(description="Whether the address is valid")
    error: str = Field(description="Error type name")
    msg: str = Field(description="Error message")


@register_resource
class ValidateAddressResource(Resource):
    """ Implements a web server API that receives a string and returns whether it's a valid address and its script.

    The actual implementation is forwarded to _ValidateAddressResource, this only instantiates that class.

    You must run with option `--status <PORT>`.
    """

    def __init__(self, manager):
        super().__init__()
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def getChild(self, name, request):
        return _ValidateAddressResource(self.manager, name)


class _ValidateAddressResource(Resource):
    """ Actual implementation of ValidateAddressResource.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager, address: Union[str, bytes]):
        super().__init__()
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        if isinstance(address, bytes):
            address = address.decode('ascii')
        assert isinstance(address, str)
        self.address = address

    @api_endpoint(
        path='/validate_address/{address}',
        method='GET',
        operation_id='validate_address',
        summary='Validate address and also create output script',
        description='Validates a Base58 address and returns its script if valid.',
        tags=['transaction'],
        visibility='public',
        rate_limit_global=[{'rate': '2000r/s', 'burst': 200, 'delay': 100}],
        rate_limit_per_ip=[{'rate': '50r/s', 'burst': 10, 'delay': 3}],
        response_model=ValidateAddressSuccessResponse,
        error_responses=[ValidateAddressErrorResponse],
        path_params_regex={'address': '.*'},
    )
    @api_catch_exceptions
    def render_GET(self, request):
        """ Get request /validate_address/<address> that returns a script if address is valid.
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        try:
            base_script = create_base_script(self.address)
        except Exception as e:
            error_response = ValidateAddressErrorResponse(
                valid=False,
                error=type(e).__name__,
                msg=str(e),
            )
            return error_response.json_dumpb()

        success_response = ValidateAddressSuccessResponse(
            valid=True,
            script=base64.b64encode(base_script.get_script()).decode('ascii'),
            address=base_script.get_address(),
            type=base_script.get_type().lower(),
        )
        return success_response.json_dumpb()
