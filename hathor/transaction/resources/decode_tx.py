from twisted.web import resource
from hathor.api_util import set_cors
from hathor.transaction import Transaction

import json
import struct
import re


class DecodeTxResource(resource.Resource):
    """ Implements a web server API that receives hex form of a tx and returns the object

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ Get request /decode_tx/ that returns the tx decoded, if success

            Expects 'hex_tx' as GET parameter

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        requested_decode = request.args[b'hex_tx'][0].decode('utf-8')

        pattern = r'[a-fA-F\d]+'
        if re.match(pattern, requested_decode) and len(requested_decode) % 2 == 0:
            tx_bytes = bytes.fromhex(requested_decode)

            try:
                tx = Transaction.create_from_struct(tx_bytes)
                tx_data = tx.to_json(decode_script=True)
                tx.storage = self.manager.tx_storage
                tx_data['accumulated_weight'] = tx.get_metadata().accumulated_weight
                data = {
                    'transaction': tx_data,
                    'success': True
                }
            except struct.error:
                data = {'success': False}

        else:
            data = {'success': False}
        return json.dumps(data, indent=4).encode('utf-8')
