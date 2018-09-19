from twisted.web import resource
from hathor.api_util import set_cors
from hathor.transaction.storage.exceptions import TransactionDoesNotExist

import json
import re


class TransactionResource(resource.Resource):
    """ Implements a web server API to return the tx.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ Get request /transaction/ that returns list of tx or a single one

            If receive 'id' (hash) as GET parameter we return the tx with this hash
            Else we return a list of tx. We expect 'type' and 'count' as parameters in this case

            'type': 'block' or 'tx', to indicate if we should return a list of blocks or tx
            'count': int, to indicate the quantity of elements we should return
            'hash': string, the hash reference we are in the pagination
            'page': 'previous' or 'next', to indicate if the user wants after or before the hash reference
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if b'id' in request.args:
            # Get one tx
            data = self.get_one_tx(request)
        else:
            # Get all tx
            data = self.get_list_tx(request)

        return json.dumps(data, indent=4).encode('utf-8')

    def get_one_tx(self, request):
        """ Get 'id' (hash) from request.args
            Returns the tx with this hash or {'success': False} if hash is invalid or tx does not exist
        """
        try:
            requested_hash = request.args[b'id'][0].decode('utf-8')
            pattern = r'[a-fA-F\d]{64}'
            # Check if parameter is a valid hex hash
            if re.match(pattern, requested_hash):
                tx = self.manager.tx_storage.get_transaction_by_hash(requested_hash)
                serialized = tx.to_json(decode_script=True)
                serialized['raw'] = tx.get_struct().hex()
                data = {
                    'success': True,
                    'tx': serialized
                }
            else:
                data = {'success': False}
        except TransactionDoesNotExist:
            data = {'success': False}

        return data

    def get_list_tx(self, request):
        """ Get parameter from request.args and return list of blocks/txs

            'type': 'block' or 'tx', to indicate if we should return a list of blocks or tx
            'count': int, to indicate the quantity of elements we should return
            'hash': string, the hash reference we are in the pagination
            'page': 'previous' or 'next', to indicate if the user wants after or before the hash reference
        """
        count = int(request.args[b'count'][0])
        type_tx = request.args[b'type'][0].decode('utf-8')
        ref_hash = None
        page = ''
        if b'hash' in request.args:
            ref_hash = request.args[b'hash'][0].decode('utf-8')
            page = request.args[b'page'][0].decode('utf-8')

        if type_tx == 'block':
            if page == 'previous':
                blocks, has_more = self.manager.tx_storage.get_blocks_before_hash(ref_hash, count)
            else:
                blocks, has_more = self.manager.tx_storage.get_blocks_after_hash(ref_hash, count)

            serialized = [block.to_json() for block in blocks]
        else:
            if page == 'previous':
                transactions, has_more = self.manager.tx_storage.get_txs_before_hash(ref_hash, count)
            else:
                transactions, has_more = self.manager.tx_storage.get_txs_after_hash(ref_hash, count)

            serialized = [tx.to_json() for tx in transactions]

        data = {
            'transactions': serialized,
            'has_more': has_more
        }
        return data
