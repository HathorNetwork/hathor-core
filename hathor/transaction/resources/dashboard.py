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

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, parse_args, parse_int, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.util import json_dumpb

ARGS = ['block', 'tx']


@register_resource
class DashboardTransactionResource(Resource):
    """ Implements a web server API to return dashboard data for tx.
        Returns some blocks and some transactions (quantity comes from the frontend)

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self._settings = get_global_settings()
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

        parsed = parse_args(get_args(request), ARGS)
        if not parsed['success']:
            return get_missing_params_msg(parsed['missing'])

        # Get quantity for each
        try:
            block_count = parse_int(parsed['args']['block'])
        except ValueError as e:
            return json_dumpb({
                'success': False,
                'message': f'Failed to parse \'block\': {e}'
            })

        try:
            tx_count = parse_int(parsed['args']['tx'])
        except ValueError as e:
            return json_dumpb({
                'success': False,
                'message': f'Failed to parse \'tx\': {e}'
            })

        # Restrict counts
        block_count = min(block_count, self._settings.MAX_DASHBOARD_COUNT)
        tx_count = min(tx_count, self._settings.MAX_DASHBOARD_COUNT)

        transactions, _ = self.manager.tx_storage.get_newest_txs(count=tx_count)
        serialized_tx = [tx.to_json_extended() for tx in transactions]

        blocks, _ = self.manager.tx_storage.get_newest_blocks(count=block_count)
        serialized_blocks = [block.to_json_extended() for block in blocks]

        data = {
            'success': True,
            'transactions': serialized_tx,
            'blocks': serialized_blocks,
        }

        return json_dumpb(data)


DashboardTransactionResource.openapi = {
    '/dashboard_tx': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '50r/s',
                    'burst': 100,
                    'delay': 50
                }
            ],
            'per-ip': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
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
                                        'success': True,
                                        'transactions': [
                                            {
                                                'tx_id': ('0002bb171de3490828028ec5eef33259'
                                                          '56acb6bcffa6a50466bb9a81d38363c2'),
                                                'timestamp': 1539271483,
                                                'version': 1,
                                                'weight': 14,
                                                'parents': [
                                                    '00000b8792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb4',
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb9'
                                                ],
                                                'inputs': [],
                                                'outputs': [],
                                                'tokens': [],
                                                'first_block': None,
                                            },
                                            {
                                                'tx_id': ('00002b3be4e3876e67b5e090d76dcd71'
                                                          'cde1a30ca1e54e38d65717ba131cd22f'),
                                                'timestamp': 1539271482,
                                                'version': 1,
                                                'weight': 14,
                                                'parents': [
                                                    '00000b8792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb5',
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb1'
                                                ],
                                                'inputs': [],
                                                'outputs': [],
                                                'tokens': [],
                                                'first_block': ('000005af290a55b079014a0be3246479'
                                                                'e84eeb635f02010dbf3e5f3414a85bbb')
                                            }
                                        ],
                                        'blocks': [
                                            {
                                                'tx_id': ('0001e29bf6271d15a6c89bffdf99a943'
                                                          '51007a3aeb63a113d33493ce28b9de19'),
                                                'timestamp': 1547143591,
                                                'height': 1233,
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
                                                'tokens': [],
                                                'first_block': ('000005af290a55b079014a0be3246479'
                                                                'e84eeb635f02010dbf3e5f3414a85bbb')
                                            },
                                            {
                                                'tx_id': ('00035e46a20d0ecbda0dc6fdcaa243e9'
                                                          '3a7120baa8c90739e0d011370576de83'),
                                                'timestamp': 1547143590,
                                                'height': 1234,
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
                                                'tokens': [],
                                                'first_block': ('000005af290a55b079014a0be3246479'
                                                                'e84eeb635f02010dbf3e5f3414a85bbb')
                                            },
                                            {
                                                'tx_id': ('000133cc80b625b1babbd454edc3474e'
                                                          '0a130dafee5d359c52aabcee3d1193ee'),
                                                'timestamp': 1547143589,
                                                'height': 1235,
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
                                                'tokens': [],
                                                'first_block': None
                                            }
                                        ]
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid parameters',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid parameter, cannot convert to int: block',
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
