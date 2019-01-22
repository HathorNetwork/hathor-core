import json

from twisted.web import resource

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.wallet.exceptions import IncorrectPassword, InvalidWords


@register_resource
class UnlockWalletResource(resource.Resource):
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
            :rtype: string (json) Dict['success', bool]
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')
        post_data = json.loads(request.content.read().decode('utf-8'))

        if 'password' in post_data:
            # Wallet keypair
            return self.unlock_wallet_keypair(post_data)
        else:
            # Wallet HD
            return self.unlock_wallet_hd(post_data)

    def unlock_wallet_hd(self, data):
        words = None
        if 'words' in data:
            words = data['words']

        passphrase = bytes(data['passphrase'], 'utf-8')
        ret = {'success': True}

        try:
            ret_words = self.manager.wallet.unlock(self.manager.tx_storage, words, passphrase)
            if not words:
                # ret_words are the newly generated words
                ret['words'] = ret_words
        except InvalidWords:
            ret['success'] = False
            ret['message'] = 'Invalid words'

        return json.dumps(ret, indent=4).encode('utf-8')

    def unlock_wallet_keypair(self, data):
        password = bytes(data['password'], 'utf-8')
        ret = {}
        success = True

        try:
            self.manager.wallet.unlock(password)
        except IncorrectPassword:
            success = False
            ret['message'] = 'Invalid password'

        ret['success'] = success
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request)


UnlockWalletResource.openapi = {
    '/wallet/unlock': {
        'post': {
            'tags': ['wallet'],
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
