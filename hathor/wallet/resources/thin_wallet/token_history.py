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

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, parse_args, parse_int, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.transaction.base_transaction import TX_HASH_SIZE
from hathor.util import json_dumpb

ARGS = ['id', 'count']


@register_resource
class TokenHistoryResource(Resource):
    """ Implements a web server API to return history of transactions of a token.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self._settings = get_global_settings()
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/token_history/

            Expects as GET parameter of the queried token:
                - 'id': uid of token whose history is being requested
                - 'count': int, to indicate the quantity of elements we should return
                - 'hash': string, the hash reference we are in the pagination
                - 'timestamp': int, the timestamp reference we are in the pagination
                - 'page': 'previous' or 'next', to indicate if the user wants after or before the hash reference

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        tokens_index = self.manager.tx_storage.indexes.tokens
        if not tokens_index:
            request.setResponseCode(503)
            return json_dumpb({'success': False})

        raw_args = get_args(request)
        parsed = parse_args(raw_args, ARGS)
        if not parsed['success']:
            return get_missing_params_msg(parsed['missing'])

        if b'id' not in raw_args:
            return get_missing_params_msg('id')

        try:
            token_uid = bytes.fromhex(parsed['args']['id'])
        except (ValueError, AttributeError):
            return json_dumpb({'success': False, 'message': 'Invalid token id'})

        if len(token_uid) != TX_HASH_SIZE:
            return json_dumpb({'success': False, 'message': 'Invalid token id'})

        try:
            count = parse_int(parsed['args']['count'], cap=self._settings.MAX_TX_COUNT)
        except ValueError as e:
            return json_dumpb({
                'success': False,
                'message': f'Failed to parse \'count\': {e}'
            })

        if b'hash' in raw_args:
            parsed = parse_args(raw_args, ['timestamp', 'page', 'hash'])
            if not parsed['success']:
                return get_missing_params_msg(parsed['missing'])

            try:
                hash_bytes = bytes.fromhex(parsed['args']['hash'])
            except ValueError as e:
                return json_dumpb({
                    'success': False,
                    'message': f'Failed to parse \'hash\': {e}'
                })

            page = parsed['args']['page']
            if page != 'previous' and page != 'next':
                return json_dumpb({
                    'success': False,
                    'message': 'Invalid \'page\' parameter, expected \'previous\' or \'next\''
                })

            try:
                ref_timestamp = parse_int(parsed['args']['timestamp'])
            except ValueError as e:
                return json_dumpb({
                    'success': False,
                    'message': f'Failed to parse \'timestamp\': {e}'
                })

            if page == 'previous':
                elements, has_more = tokens_index.get_newer_transactions(
                        token_uid, ref_timestamp, hash_bytes, count)
            else:
                elements, has_more = tokens_index.get_older_transactions(
                        token_uid, ref_timestamp, hash_bytes, count)
        else:
            elements, has_more = tokens_index.get_newest_transactions(token_uid, count)

        transactions = [self.manager.tx_storage.get_transaction(element) for element in elements]
        serialized = [tx.to_json_extended() for tx in transactions]

        data = {
            'success': True,
            'transactions': serialized,
            'has_more': has_more,
        }
        return json_dumpb(data)


TokenHistoryResource.openapi = {
    '/thin_wallet/token_history': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '100r/s',
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
            'tags': ['wallet'],
            'operationId': 'tokenHistory',
            'summary': 'Get history transactions of a token',
            'parameters': [
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
                },
                {
                    'name': 'timestamp',
                    'in': 'query',
                    'description': 'Timestamp reference for the pagination',
                    'required': False,
                    'schema': {
                        'type': 'integer'
                    }
                },
                {
                    'name': 'id',
                    'in': 'query',
                    'description': 'Token id',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'transactions': [
                                            {
                                                'tx_id': ('00000257054251161adff5899a451ae9'
                                                          '74ac62ca44a7a31179eec5750b0ea406'),
                                                'nonce': 99579,
                                                'timestamp': 1547163030,
                                                'version': 1,
                                                'weight': 18.861583646228,
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
                                                'tokens': [],
                                                'first_block': None
                                            },
                                            {
                                                'tx_id': ('00000b8792cb13e8adb51cc7d866541f'
                                                          'c29b532e8dec95ae4661cf3da4d42cb4'),
                                                'nonce': 119816,
                                                'timestamp': 1547163025,
                                                'version': 1,
                                                'weight': 17.995048894541107,
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
                                                'tokens': [],
                                                'first_block': ('000005af290a55b079014a0be3246479'
                                                                'e84eeb635f02010dbf3e5f3414a85bbb')
                                            }
                                        ],
                                        'has_more': True
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid token id',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid token id',
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}
