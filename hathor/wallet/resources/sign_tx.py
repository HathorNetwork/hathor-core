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

import re
import struct

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, set_cors
from hathor.transaction import Transaction
from hathor.util import json_dumpb


@register_resource
class SignTxResource(Resource):
    """ Implements a web server API that receives hex form of a tx and signs the inputs
    belonging to the user's wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request /decode_tx/ that returns the signed tx, if success

            Expects 'hex_tx' as GET parameter

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        raw_args = get_args(request)
        if b'hex_tx' in raw_args:
            requested_decode = raw_args[b'hex_tx'][0].decode('utf-8')
        else:
            return get_missing_params_msg('hex_tx')

        pattern = r'[a-fA-F\d]+'
        if re.match(pattern, requested_decode) and len(requested_decode) % 2 == 0:
            tx_bytes = bytes.fromhex(requested_decode)

            prepare_to_send = False
            if b'prepare_to_send' in raw_args:
                _prepare_to_send = raw_args[b'prepare_to_send'][0].decode('utf-8')
                prepare_to_send = _prepare_to_send == 'true'

            try:
                tx = Transaction.create_from_struct(tx_bytes)
                tx.storage = self.manager.tx_storage
                self.manager.wallet.sign_transaction(tx, self.manager.tx_storage)

                if prepare_to_send:
                    tx.parents = self.manager.get_new_tx_parents()
                    tx.update_timestamp(int(self.manager.reactor.seconds()))
                    tx.weight = self.manager.daa.minimum_tx_weight(tx)
                    self.manager.cpu_mining_service.resolve(tx)

                data = {'hex_tx': tx.get_struct().hex(), 'success': True}
            except struct.error:
                data = {'success': False, 'message': 'Transaction invalid'}

        else:
            data = {'success': False, 'message': 'Transaction invalid'}
        return json_dumpb(data)


SignTxResource.openapi = {
    '/wallet/sign_tx': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_sign_tx',
            'summary': 'Sign transaction',
            'description': ('Returns a transaction after signing. If "prepare_to_send" is true,'
                            ' it also add the parents, weight, timestamp and solves proof-of-work.'),
            'parameters': [
                {
                    'name': 'hex_tx',
                    'in': 'query',
                    'description': 'Transaction in hex to be signed',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'prepare_to_send',
                    'in': 'query',
                    'description': 'If proof-of-work should be done',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
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
                                    'summary': 'Success',
                                    'value': {
                                        'hex_tx': ('00014032dc90beef51545c37d59600000000000000000002000200020000000b8'
                                                   '792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb400001417'
                                                   '652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb90000088c5'
                                                   'a4dfcef7fd3c04a5b1eccfd2de032b23749deff871b0a090000f5f601006a4730'
                                                   '45022100befd7bbe9f17c8762adfa3c594e19ded5dafcc891ff9722ea9fc949dc'
                                                   'd9f66e8022039f033b3dd900feac2dd905cb0775a77a0b5d3aa57c82ff87eb7be'
                                                   '85956ec49c2103ea83bcb645a9d376741c0ef167788ce3ad4cc9a0fce49a8352b'
                                                   '6837c5ed2d3500000003398322f99355f37439e32881c83ff08b83e744e799b1d'
                                                   '6a67f73bee4500006a473045022100a8fbc3d7c53377a36c31590631a23d46cc5'
                                                   '6a8ba30db65b52811d4516ff7e54102204514f69c4910706f5f2130600076fdb0'
                                                   'a25b135de222efcaf41718a6926835762103c32f7899bec0d2f237450e695cbdc'
                                                   'd849bf64d6180ce056777a195b1a6e0390d0000077500001976a9149651450c90'
                                                   '725794e3554972dd97376c1e26307d88ac0000003700001976a9148e33e0fb3c0'
                                                   '6e890def74d48d326d0c5c00fac0b88ac000184fb'),
                                        'success': True
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid transaction',
                                    'value': {
                                        'success': False,
                                        'message': 'Transaction invalid'
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
