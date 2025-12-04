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

from typing import Any

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.util import is_token_uid_valid, json_dumpb

_MAX_UTXO_LIST_LENGTH: int = 100


@register_resource
class TokenResource(Resource):
    """ Implements a web server API to return token information.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self._settings = get_global_settings()
        self.manager = manager

    def get_one_token_data(self, token_uid: bytes) -> dict[str, Any]:
        # Get one token data specified in id
        tokens_index = self.manager.tx_storage.indexes.tokens
        try:
            token_info = tokens_index.get_token_info(token_uid)
        except KeyError:
            return {'success': False, 'message': 'Unknown token'}

        mint: list[dict[str, Any]] = []
        melt: list[dict[str, Any]] = []

        transactions_count = tokens_index.get_transactions_count(token_uid)

        for tx_hash, index in token_info.iter_mint_utxos():
            if len(mint) >= _MAX_UTXO_LIST_LENGTH:
                break
            mint.append({
                'tx_id': tx_hash.hex(),
                'index': index
            })

        for tx_hash, index in token_info.iter_melt_utxos():
            if len(melt) >= _MAX_UTXO_LIST_LENGTH:
                break
            melt.append({
                'tx_id': tx_hash.hex(),
                'index': index
            })

        data = {
            'name': token_info.get_name(),
            'symbol': token_info.get_symbol(),
            'version': token_info.get_version(),
            'success': True,
            # XXX: mint and melt keys are deprecated and we should remove them from the API soon.
            #      They're a truncated list with up to _MAX_UTXO_LIST_LENGTH items.
            'mint': mint,
            'melt': melt,
            'can_mint': token_info.can_mint(),
            'can_melt': token_info.can_melt(),
            'total': token_info.get_total(),
            'transactions_count': transactions_count,
        }
        return data

    def get_list_token_data(self) -> dict[str, Any]:
        # XXX We should change this in the future so we don't return all tokens in one request
        # XXX Right now, the way we have the tokens index is not easy to do it but in the future
        # XXX when the number of tokens grow we should refactor this resource
        # XXX For now we only set a fixed limit of 200 tokens to return

        # Get all tokens
        all_tokens = self.manager.tx_storage.indexes.tokens.iter_all_tokens()

        tokens = []
        count = 0
        limit = 200
        truncated = False
        for uid, token_info in all_tokens:
            if uid == self._settings.HATHOR_TOKEN_UID:
                continue

            if count >= limit:
                truncated = True
                break

            tokens.append(
                {
                    'uid': uid.hex(),
                    'name': token_info.get_name(),
                    'symbol': token_info.get_symbol(),
                    'version': token_info.get_version(),
                }
            )

            count += 1

        data = {
            'success': True,
            'tokens': tokens,
            'truncated': truncated,
        }
        return data

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/token/

            Expects 'id' (hash) as GET parameter of the queried token

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.tx_storage.indexes.tokens:
            request.setResponseCode(503)
            return json_dumpb({'success': False})

        raw_args = get_args(request)
        if b'id' in raw_args:
            try:
                token_uid_str = raw_args[b'id'][0].decode('utf-8')
                token_uid = bytes.fromhex(token_uid_str)
            except (ValueError, AttributeError):
                return json_dumpb({'success': False, 'message': 'Invalid token id'})

            if not is_token_uid_valid(token_uid):
                return json_dumpb({'success': False, 'message': 'Invalid token id format'})

            data = self.get_one_token_data(token_uid)
        else:
            data = self.get_list_token_data()

        return json_dumpb(data)


TokenResource.openapi = {
    '/thin_wallet/token': {
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
            'operationId': 'token',
            'summary': 'Get information about a token if send token ID, otherwise return list of tokens',
            'parameters': [
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
                                        'name': 'MyCoin',
                                        'symbol': 'MYC',
                                        'version': 1,
                                        'mint': [
                                            {
                                                "tx_id": "00000299670db5814f69cede8b347f83"
                                                         "0f73985eaa4cd1ce87c9a7c793771336",
                                                "index": 0
                                            }
                                        ],
                                        'melt': [
                                            {
                                                "tx_id": "00000299670db5814f69cede8b347f83"
                                                         "0f73985eaa4cd1ce87c9a7c793771336",
                                                "index": 1
                                            }
                                        ],
                                        'can_mint': True,
                                        'can_melt': True,
                                        'total': 50000,
                                        'transactions_count': 3,
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid token id',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid token id',
                                    }
                                },
                                'success_list': {
                                    'summary': 'List of tokens success',
                                    'value': {
                                        'success': True,
                                        'truncated': False,
                                        'tokens': [
                                            {
                                                'uid': "00000b1b8b1df522489f9aa38cba82a4"
                                                       "50b1fe58093e97bc94a0275fbeb226b2",
                                                'name': 'MyCoin',
                                                'symbol': 'MYC',
                                                'version': 1,
                                            },
                                            {
                                                'uid': "00000093f76f44c664907a017bbf9ef6"
                                                       "bb289692e30c7cf7361e6872c5ee1796",
                                                'name': 'New Token',
                                                'symbol': 'NTK',
                                                'version': 1,
                                            },
                                        ],
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
