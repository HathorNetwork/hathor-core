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

from typing import Any

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, render_options, set_cors
from hathor.util import json_dumpb, json_loadb
from hathor.wallet.exceptions import IncorrectPassword, InvalidWords


@register_resource
class UnlockWalletResource(Resource):
    """ Implements a web server API a POST to unlock the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the wallet
        self.manager = manager

    def render_POST(self, request):
        """ Tries to unlock the wallet
            One parameter is expected in request.args

            :param password: Password to unlock the wallet
            :type password: string

            :return: Boolean if the user unlocked the wallet with success
            :rtype: string (json) dict['success', bool]
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')
        post_data = json_loadb(request.content.read())

        if 'password' in post_data:
            # Wallet keypair
            return self.unlock_wallet_keypair(post_data)
        else:
            # Wallet HD
            return self.unlock_wallet_hd(post_data)

    def unlock_wallet_hd(self, data: dict[str, Any]) -> bytes:
        words = None
        if 'words' in data:
            words = data['words']

        passphrase = bytes(data['passphrase'], 'utf-8')
        ret: dict[str, Any] = {'success': True}

        try:
            ret_words = self.manager.wallet.unlock(self.manager.tx_storage, words, passphrase)
            if not words:
                # ret_words are the newly generated words
                ret['words'] = ret_words
        except InvalidWords:
            ret['success'] = False
            ret['message'] = 'Invalid words'

        return json_dumpb(ret)

    def unlock_wallet_keypair(self, data: dict[str, Any]) -> bytes:
        password = bytes(data['password'], 'utf-8')
        ret: dict[str, Any] = {}
        success = True

        try:
            self.manager.wallet.unlock(password)
        except IncorrectPassword:
            success = False
            ret['message'] = 'Invalid password'

        ret['success'] = success
        return json_dumpb(ret)

    def render_OPTIONS(self, request):
        return render_options(request)


UnlockWalletResource.openapi = {
    '/wallet/unlock': {
        'x-visibility': 'private',
        'post': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_unlock',
            'summary': 'Unlock a wallet',
            'description': ('Unlock HD Wallet or Keypair Wallet, depending on the parameters sent. For Keypair Wallet'
                            'we need the password and for HD Wallet the passphrase and the words (optional)'),
            'requestBody': {
                'description': 'Data to unlock your wallet',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/UnlockBody'
                        },
                        'examples': {
                            'unlock_hd_with_words': {
                                'summary': 'HD Wallet complete',
                                'value': {
                                    'passphrase': '1234',
                                    'words': ('yellow viable junk brand mosquito sting rhythm stumble cricket report '
                                              'circle elite gasp kingdom spy capable beach peanut plastic finish '
                                              'robot venue mixture talent')
                                }
                            },
                            'unlock_hd_without_words': {
                                'summary': 'HD Wallet no words',
                                'value': {
                                    'passphrase': '1234'
                                }
                            },
                            'unlock_hd_without_anything': {
                                'summary': 'HD Wallet with nothing',
                                'value': {
                                    'passphrase': ''
                                }
                            },
                            'unlock_keypair': {
                                'summary': 'Data to unlock keypair wallet',
                                'value': {
                                    'password': '1234'
                                }
                            }
                        }
                    }
                }
            },
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success_hd': {
                                    'summary': 'HD Wallet unlocked',
                                    'value': {
                                      'success': True,
                                      'words': ('yellow viable junk brand mosquito sting rhythm stumble cricket report'
                                                ' circle elite gasp kingdom spy capable beach peanut plastic finish'
                                                ' robot venue mixture talent')
                                    }
                                },
                                'success_keypair': {
                                    'summary': 'Keypair Wallet unlocked',
                                    'value': {
                                      'success': True
                                    }
                                },
                                'error_hd': {
                                    'summary': 'Error unlocking HD wallet',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid words'
                                    }
                                },
                                'error_keypair': {
                                    'summary': 'Error unlocking keypair wallet',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid password'
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
