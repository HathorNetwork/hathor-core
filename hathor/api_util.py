import re
from typing import Tuple

from twisted.web.http import Request

from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist


def set_cors(request: Request, method: str) -> None:
    request.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000')
    request.setHeader('Access-Control-Allow-Methods', method)
    request.setHeader('Access-Control-Allow-Headers', 'x-prototype-version,x-requested-with,content-type')
    request.setHeader('Access-Control-Max-Age', 604800)


def render_options(request: Request, verbs: str = 'GET, POST, OPTIONS') -> int:
    """Function to return OPTIONS request.

    Most of the APIs only need it for GET, POST and OPTIONS, but verbs can be passed as parameter.

    :param verbs: verbs to reply on render options
    :type verbs: str
    """
    from twisted.web import server
    set_cors(request, verbs)
    request.setHeader(b'content-type', b'application/json; charset=utf-8')
    request.write(b'')
    request.finish()
    return server.NOT_DONE_YET


def get_missing_params_msg(param_name):
    """Util function to return error response when a parameter is missing

    :param param_name: the missing parameter
    :type param_name: str
    """
    import json
    return json.dumps({'success': False, 'message': 'Missing parameter: {}'.format(param_name)}).encode('utf-8')


def validate_tx_hash(hash_hex: str, tx_storage: TransactionStorage) -> Tuple[bool, str]:
    """ Validate if the tx hash is valid and if it exists
        Return success and a message in case of failure
    """
    success = True
    message = ''
    pattern = r'[a-fA-F\d]{64}'
    # Check if parameter is a valid hex hash
    if not re.match(pattern, hash_hex):
        success = False
        message = 'Invalid hash'
    else:
        try:
            tx_storage.get_transaction(bytes.fromhex(hash_hex))
        except TransactionDoesNotExist:
            success = False
            message = 'Transaction not found'

    return success, message
