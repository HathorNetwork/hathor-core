import json

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class AddressHistoryResource(resource.Resource):
    """ Implements a web server API to return the address history

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/address_history/
            Expects 'addresses[]' as request args
            'addresses[]' is an array of address

            Returns an array of WalletIndex for each address

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.tx_storage.wallet_index:
            request.setResponseCode(503)
            return json.dumps({'success': False}, indent=4).encode('utf-8')

        addresses = request.args[b'addresses[]']

        history = []

        for address_to_decode in addresses:
            address = address_to_decode.decode('utf-8')
            history_data = [data.__dict__ for data in self.manager.tx_storage.wallet_index.get_from_address(address)]
            history.append({'address': address, 'history': history_data})

        data = {'history': history}
        return json.dumps(data, indent=4).encode('utf-8')


AddressHistoryResource.openapi = {
    '/thin_wallet/address_history': {
        'get': {
            'tags': ['thin_wallet'],
            'operationId': 'address_history',
            'summary': 'History of some addresses',
            'parameters': [
                {
                    'name': 'addresses[]',
                    'in': 'query',
                    'description': 'Stringified array of addresses',
                    'required': True,
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
                                    'summary': 'Success',
                                    'value': {
                                        'history': [
                                            {
                                                'address': '1DSTD8ZUxthNb92Jv1RdfGucpYRusgKLD8',
                                                'history': [
                                                    {
                                                        'from_tx_id': ('0000717da0cc0c039924618739dc9db1'
                                                                       '084d8e3d7a1fef633312d7dd7ef6cc7f'),
                                                        'index': 1,
                                                        'is_output': False,
                                                        'timelock': None,
                                                        'timestamp': 1548730067,
                                                        'token_uid': '00',
                                                        'tx_id': ('0000227b84363e7b1f0f41dbd968ef3e'
                                                                  '2b941fdf23342fd80d78cf98685b0265'),
                                                        'value': 500,
                                                        'voided': False
                                                    },
                                                    {
                                                        'index': 1,
                                                        'is_output': True,
                                                        'timelock': None,
                                                        'timestamp': 1548730067,
                                                        'token_uid': '00',
                                                        'tx_id': ('0000227b84363e7b1f0f41dbd968ef3e'
                                                                  '2b941fdf23342fd80d78cf98685b0265'),
                                                        'value': 200,
                                                        'voided': False
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid address',
                                    'value': {
                                        'success': False,
                                        'message': 'The address xx is invalid',
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
