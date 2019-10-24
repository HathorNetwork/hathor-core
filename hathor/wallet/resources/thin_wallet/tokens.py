import json

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import get_missing_params_msg, set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class TokenResource(resource.Resource):
    """ Implements a web server API to return token information.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/token/

            Expects 'id' (hash) as GET parameter of the queried token

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.tx_storage.tokens_index:
            request.setResponseCode(503)
            return json.dumps({'success': False}).encode('utf-8')

        if b'id' not in request.args:
            return get_missing_params_msg('id')

        try:
            token_uid_str = request.args[b'id'][0].decode('utf-8')
            token_uid = bytes.fromhex(token_uid_str)
        except (ValueError, AttributeError):
            return json.dumps({'success': False, 'message': 'Invalid token id'}).encode('utf-8')

        try:
            token_info = self.manager.tx_storage.tokens_index.get_token_info(token_uid)
        except KeyError:
            return json.dumps({'success': False, 'message': 'Unknown token'}).encode('utf-8')

        mint = []
        melt = []

        transactions_count = self.manager.tx_storage.tokens_index.get_transactions_count(token_uid)

        for tx_hash, index in token_info.mint:
            mint.append({
                'tx_id': tx_hash.hex(),
                'index': index
            })

        for tx_hash, index in token_info.melt:
            melt.append({
                'tx_id': tx_hash.hex(),
                'index': index
            })

        data = {
            'name': token_info.name,
            'symbol': token_info.symbol,
            'success': True,
            'mint': mint,
            'melt': melt,
            'total': token_info.total,
            'transactions_count': transactions_count,
        }
        return json.dumps(data).encode('utf-8')


TokenResource.openapi = {
    '/thin_wallet/token': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '100r/s',
                    'burst': 100,
                    'delay': 50
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
            'tags': ['thin_wallet'],
            'operationId': 'token',
            'summary': 'Get information about a token',
            'parameters': [
                {
                    'name': 'id',
                    'in': 'query',
                    'description': 'Token id',
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
                                        'success': True,
                                        'name': 'MyCoin',
                                        'symbol': 'MYC',
                                        'mint': [
                                            {
                                                "tx_id": "00000299670db5814f69cede8b347f83"
                                                         "0f73985eaa4cd1ce87c9a7c793771336",
                                                "index": 0
                                            }
                                        ],
                                        'melt': [
                                            {
                                                "tx_id": "00000299670db5814f69cede8b347f83"
                                                         "0f73985eaa4cd1ce87c9a7c793771336",
                                                "index": 1
                                            }
                                        ],
                                        'total': 50000,
                                        'transactions_count': 3,
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid token id',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid token id',
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
