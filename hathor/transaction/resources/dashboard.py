import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings

settings = HathorSettings()


@register_resource
class DashboardTransactionResource(resource.Resource):
    """ Implements a web server API to return dashboard data for tx.
        Returns some blocks and some transactions (quantity comes from the frontend)

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ Get request to /dashboard-tx/ that return a list of blocks and tx
            We expect two GET parameters: 'block' and 'tx'

            'block': int that indicates de quantity of blocks I should return
            'tx': int that indicates de quantity of tx I should return

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # Get quantity for each
        block_count = int(request.args[b'block'][0])
        tx_count = int(request.args[b'tx'][0])

        # Restrict counts
        block_count = min(block_count, settings.MAX_DASHBOARD_COUNT)
        tx_count = min(tx_count, settings.MAX_DASHBOARD_COUNT)

        transactions, _ = self.manager.tx_storage.get_newest_txs(count=tx_count)
        serialized_tx = [tx.to_json_extended() for tx in transactions]

        blocks, _ = self.manager.tx_storage.get_newest_blocks(count=block_count)
        serialized_blocks = [block.to_json_extended() for block in blocks]

        data = {
            'transactions': serialized_tx,
            'blocks': serialized_blocks,
        }

        return json.dumps(data, indent=4).encode('utf-8')


DashboardTransactionResource.openapi = {
    '/dashboard_tx': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '1000r/s',
                    'burst': 1000,
                    'delay': 500
                }
            ],
            'per-ip': [
                {
                    'rate': '5r/s'
                }
            ]
        },
        'get': {
            'tags': ['transaction'],
            'operationId': 'dashboard_tx',
            'summary': 'Dashboard of transactions',
            'parameters': [
                {
                    'name': 'tx',
                    'in': 'query',
                    'description': 'Quantity of transactions in the dashboard',
                    'required': True,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'block',
                    'in': 'query',
                    'description': 'Quantity of blocks in the dashboard',
                    'required': True,
                    'schema': {
                        'type': 'int'
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
                                    'summary': 'Transaction decoded',
                                    'value': {
                                        'transactions': [
                                            {
                                                'tx_id': ('0002bb171de3490828028ec5eef33259'
                                                          '56acb6bcffa6a50466bb9a81d38363c2'),
                                                'nonce': 91696,
                                                'timestamp': 1539271483,
                                                'version': 1,
                                                'weight': 14,
                                                'parents': [],
                                                'inputs': [],
                                                'outputs': [],
                                                'tokens': []
                                            },
                                            {
                                                'tx_id': ('00002b3be4e3876e67b5e090d76dcd71'
                                                          'cde1a30ca1e54e38d65717ba131cd22f'),
                                                'nonce': 17076,
                                                'timestamp': 1539271482,
                                                'version': 1,
                                                'weight': 14,
                                                'parents': [],
                                                'inputs': [],
                                                'outputs': [],
                                                'tokens': []
                                            }
                                        ],
                                        'blocks': [
                                            {
                                                'tx_id': ('0001e29bf6271d15a6c89bffdf99a943'
                                                          '51007a3aeb63a113d33493ce28b9de19'),
                                                'nonce': 20133,
                                                'timestamp': 1547143591,
                                                'version': 1,
                                                'weight': 14,
                                                'parents': [
                                                    '00035e46a20d0ecbda0dc6fdcaa243e93a7120baa8c90739e0d011370576de83',
                                                    '0002bb171de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c2',
                                                    '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f'
                                                ],
                                                'inputs': [],
                                                'outputs': [
                                                    {
                                                        'value': 2000,
                                                        'script': 'dqkUixvdsajkV6vO+9Jjgjbaheqn016IrA=='
                                                    }
                                                ],
                                                'tokens': []
                                            },
                                            {
                                                'tx_id': ('00035e46a20d0ecbda0dc6fdcaa243e9'
                                                          '3a7120baa8c90739e0d011370576de83'),
                                                'nonce': 6024,
                                                'timestamp': 1547143590,
                                                'version': 1,
                                                'weight': 14,
                                                'parents': [
                                                    '000133cc80b625b1babbd454edc3474e0a130dafee5d359c52aabcee3d1193ee',
                                                    '0002bb171de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c2',
                                                    '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f'
                                                ],
                                                'inputs': [],
                                                'outputs': [
                                                    {
                                                        'value': 2000,
                                                        'script': 'dqkUdNQbj29Md1xsAYinK+RsDJCCB7eIrA=='
                                                    }
                                                ],
                                                'tokens': []
                                            },
                                            {
                                                'tx_id': ('000133cc80b625b1babbd454edc3474e'
                                                          '0a130dafee5d359c52aabcee3d1193ee'),
                                                'nonce': 4527,
                                                'timestamp': 1547143589,
                                                'version': 1,
                                                'weight': 14,
                                                'parents': [
                                                    '0001e298570e37d46f9101bcf903bde67186f26a83d88b9cb196f38b49623457',
                                                    '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                                    '0002bb171de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c2'
                                                ],
                                                'inputs': [],
                                                'outputs': [
                                                    {
                                                        'value': 2000,
                                                        'script': 'dqkU0AoLEAX+1b36s+VyaMc9bkj/5byIrA=='
                                                    }
                                                ],
                                                'tokens': []
                                            }
                                        ]
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
