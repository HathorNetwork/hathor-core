from twisted.web import resource, server
from hathor.api_util import set_cors
from hathor.wallet.exceptions import IncorrectPassword, InvalidWords

import json


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

        if b'password' in request.args:
            # Wallet keypair
            return self.unlock_wallet_keypair(request)
        else:
            # Wallet HD
            return self.unlock_wallet_hd(request)

    def unlock_wallet_hd(self, request):
        words = None
        if b'words' in request.args:
            words = request.args[b'words'][0].decode('utf-8')

        passphrase = request.args[b'passphrase'][0]
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

    def unlock_wallet_keypair(self, request):
        password = request.args[b'password'][0]
        success = True

        try:
            self.manager.wallet.unlock(password)
        except IncorrectPassword:
            success = False

        ret = {'success': success}
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        set_cors(request, 'GET, POST, OPTIONS')
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        request.write('')
        request.finish()
        return server.NOT_DONE_YET
