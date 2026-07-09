# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor._openapi.register import register_resource
from hathor.api_util import APIVersion, Resource, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.manager import HathorManager
from hathor.util import json_dumpb


@register_resource
class BalanceResource(Resource):
    """ Implements a web server API to return the balance of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager, api_version: APIVersion) -> None:
        super().__init__(api_version)
        self._settings = get_global_settings()
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/balance/
            Returns the int balance of the wallet

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.wallet:
            return {'success': False, 'message': 'No wallet started on node'}

        wallet_balance = self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID]
        data = {
            'success': True,
            'balance': {
                'available': self.api_version.unsigned_amount_to_response(wallet_balance.available),
                'locked': self.api_version.unsigned_amount_to_response(wallet_balance.locked),
            },
        }
        return json_dumpb(data)


BalanceResource.openapi = {
    '/v1a/wallet/balance': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_address',
            'summary': 'Balance',
            'description': 'Returns the current balance of the wallet (available and locked tokens)',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'balance': {
                                            'available': 5000,
                                            'locked': 1000
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    '/v2/wallet/balance': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_address',
            'summary': 'Balance',
            'description': 'Returns the current balance of the wallet (available and locked tokens)',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'balance': {
                                            'available': '1.0',
                                            'locked': '1.0'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    },
}
