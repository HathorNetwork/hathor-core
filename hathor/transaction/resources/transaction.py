import json
import re

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.transaction.storage.exceptions import TransactionDoesNotExist


@register_resource
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

            :rtype: string (json)
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
                hash_bytes = bytes.fromhex(requested_hash)
                tx = self.manager.tx_storage.get_transaction(hash_bytes)
                serialized = tx.to_json(decode_script=True)
                serialized['raw'] = tx.get_struct().hex()
                meta = tx.update_accumulated_weight()
                serialized['accumulated_weight'] = meta.accumulated_weight
                if meta.conflict_with:
                    serialized['conflict_with'] = [h.hex() for h in meta.conflict_with]
                if meta.voided_by:
                    serialized['voided_by'] = [h.hex() for h in meta.voided_by]
                if meta.twins:
                    serialized['twins'] = [h.hex() for h in meta.twins]

                data = {'success': True, 'tx': serialized}
            else:
                data = {'success': False, 'message': 'Transaction not found'}
        except TransactionDoesNotExist:
            data = {'success': False, 'message': 'Transaction not found'}

        return data

    def get_list_tx(self, request):
        """ Get parameter from request.args and return list of blocks/txs

            'type': 'block' or 'tx', to indicate if we should return a list of blocks or tx
            'count': int, to indicate the quantity of elements we should return
            'hash': string, the hash reference we are in the pagination
            'timestamp': int, the timestamp reference we are in the pagination
            'page': 'previous' or 'next', to indicate if the user wants after or before the hash reference
        """
        count = int(request.args[b'count'][0])
        type_tx = request.args[b'type'][0].decode('utf-8')
        ref_hash = None
        page = ''
        if b'hash' in request.args:
            ref_hash = request.args[b'hash'][0].decode('utf-8')
            ref_timestamp = int(request.args[b'timestamp'][0].decode('utf-8'))
            page = request.args[b'page'][0].decode('utf-8')

            if type_tx == 'block':
                if page == 'previous':
                    elements, has_more = self.manager.tx_storage.get_newer_blocks_after(
                        ref_timestamp, bytes.fromhex(ref_hash), count)
                else:
                    elements, has_more = self.manager.tx_storage.get_older_blocks_after(
                        ref_timestamp, bytes.fromhex(ref_hash), count)

            else:
                if page == 'previous':
                    elements, has_more = self.manager.tx_storage.get_newer_txs_after(
                        ref_timestamp, bytes.fromhex(ref_hash), count)
                else:
                    elements, has_more = self.manager.tx_storage.get_older_txs_after(
                        ref_timestamp, bytes.fromhex(ref_hash), count)
        else:
            if type_tx == 'block':
                elements, has_more = self.manager.tx_storage.get_newest_blocks(count=count)
            else:
                elements, has_more = self.manager.tx_storage.get_newest_txs(count=count)

        serialized = [element.to_json() for element in elements]

        data = {'transactions': serialized, 'has_more': has_more}
        return data


TransactionResource.openapi = {
    '/transaction': {
        'get': {
            'tags': ['transaction'],
            'operationId': 'transaction',
            'summary': 'Transaction or list of transactions/blocks',
            'description': ('Returns a transaction by hash or a list of transactions/blocks depending on the '
                            'parameters sent. If "id" is sent as parameter, we return only one transaction, '
                            'else we return a list. In the list return we have a key "has_more" that indicates'
                            'if there are more transactions/blocks to be fetched'),
            'parameters': [
                {
                    'name': 'id',
                    'in': 'query',
                    'description': 'Hash in hex of the transaction/block',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'type',
                    'in': 'query',
                    'description': 'Type of list to return (block or tx)',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'count',
                    'in': 'query',
                    'description': 'Quantity of elements to return',
                    'required': False,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'page',
                    'in': 'query',
                    'description': 'If the user clicked "previous" or "next" button',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'hash',
                    'in': 'query',
                    'description': 'Hash reference for the pagination',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                }
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'One success',
                                    'value': {
                                        'tx': {
                                            'hash': '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            'nonce': 17076,
                                            'timestamp': 1539271482,
                                            'version': 1,
                                            'weight': 14.0,
                                            'height': 1,
                                            'parents': [],
                                            'inputs': [],
                                            'outputs': [],
                                            'tokens': [],
                                            'accumulated_weight': 14
                                        },
                                        'success': True
                                    }
                                },
                                'error': {
                                    'summary': 'Transaction not found',
                                    'value': {
                                        'success': False,
                                        'message': 'Transaction not found'
                                    }
                                },
                                'success_list': {
                                    'summary': 'List success',
                                    'value': {
                                        'transactions': [
                                            {
                                                'hash': ('00000257054251161adff5899a451ae9'
                                                         '74ac62ca44a7a31179eec5750b0ea406'),
                                                'nonce': 99579,
                                                'timestamp': 1547163030,
                                                'version': 1,
                                                'weight': 18.861583646228,
                                                'height': 0,
                                                'parents': [
                                                    '00000b8792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb4',
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb9'
                                                ],
                                                'inputs': [
                                                    {
                                                        'tx_id': ('0000088c5a4dfcef7fd3c04a5b1eccfd'
                                                                  '2de032b23749deff871b0a090000f5f6'),
                                                        'index': 1,
                                                        'data': ('RzBFAiEAvv17vp8XyHYq36PFlOGd7V2vzIkf+XIuqfyUnc2fZugC'
                                                                 'IDnwM7PdkA/qwt2QXLB3WnegtdOqV8gv+H63voWVbsScIQPqg7y2'
                                                                 'RanTdnQcDvFneIzjrUzJoPzkmoNStoN8XtLTUA==')
                                                    },
                                                    {
                                                        'tx_id': ('0000003398322f99355f37439e32881c'
                                                                  '83ff08b83e744e799b1d6a67f73bee45'),
                                                        'index': 0,
                                                        'data': ('RzBFAiEAqPvD18Uzd6NsMVkGMaI9RsxWqLow22W1KBHUUW/35UEC'
                                                                 'IEUU9pxJEHBvXyEwYAB2/bCiWxNd4iLvyvQXGKaSaDV2IQPDL3iZ'
                                                                 'vsDS8jdFDmlcvc2Em/ZNYYDOBWd3oZWxpuA5DQ==')
                                                    }
                                                ],
                                                'outputs': [
                                                    {
                                                        'value': 1909,
                                                        'script': 'dqkUllFFDJByV5TjVUly3Zc3bB4mMH2IrA=='
                                                    },
                                                    {
                                                        'value': 55,
                                                        'script': 'dqkUjjPg+zwG6JDe901I0ybQxcAPrAuIrA=='
                                                    }
                                                ],
                                                'tokens': []
                                            },
                                            {
                                                'hash': ('00000b8792cb13e8adb51cc7d866541f'
                                                         'c29b532e8dec95ae4661cf3da4d42cb4'),
                                                'nonce': 119816,
                                                'timestamp': 1547163025,
                                                'version': 1,
                                                'weight': 17.995048894541107,
                                                'height': 0,
                                                'parents': [
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb9',
                                                    '0000088c5a4dfcef7fd3c04a5b1eccfd2de032b23749deff871b0a090000f5f6'
                                                ],
                                                'inputs': [
                                                    {
                                                        'tx_id': ('0000088c5a4dfcef7fd3c04a5b1eccfd'
                                                                  '2de032b23749deff871b0a090000f5f6'),
                                                        'index': 0,
                                                        'data': ('SDBGAiEA/rtsn1oQ68uGeTj/7IVtqijxoUxzr9S/u3UGAC7wQvU'
                                                                 'CIQDaYkL1R8LICfSCpYIn4xx6A+lxU0Fw3oKR1hK91fRnSiEDCo'
                                                                 'A74tfBQa4IR7iXtlz+jH9UV7+YthKX4yQNaMSMfb0=')
                                                    }
                                                ],
                                                'outputs': [
                                                    {
                                                        'value': 1894,
                                                        'script': 'dqkUduvtU77hZm++Pwavtl9OrOSA+XiIrA=='
                                                    },
                                                    {
                                                        'value': 84,
                                                        'script': 'dqkUjjPg+zwG6JDe901I0ybQxcAPrAuIrA=='
                                                    }
                                                ],
                                                'tokens': []
                                            }
                                        ],
                                        'has_more': True
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
