from twisted.web import resource, server
from hathor.api_util import set_cors
from hathor.wallet.exceptions import IncorrectPassword

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
