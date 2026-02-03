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

from json import JSONDecodeError
from typing import Any, Optional

from structlog import get_logger
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import decode_address
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import json_dumpb, json_loadb
from hathor.wallet.exceptions import InvalidAddress

logger = get_logger()


@register_resource
class AddressHistoryResource(Resource):
    """ Implements a web server API to return the address history

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager
        self._log = logger.new()
        settings = get_global_settings()
        # XXX: copy the parameters that are needed so tests can more easily tweak them
        self.max_tx_addresses_history = settings.MAX_TX_ADDRESSES_HISTORY
        self.max_inputs_outputs_address_history = settings.MAX_INPUTS_OUTPUTS_ADDRESS_HISTORY

    # TODO add openapi docs for this API
    def render_POST(self, request: Request) -> bytes:
        """ POST request for /thin_wallet/address_history/

            It has the same behaviour as the GET request but when using the GET
            we have a limit of addresses to put as query param, otherwise we end up
            reaching the HTTP content length limit
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        if error_message := self._validate_index(request):
            return error_message

        assert request.content is not None
        raw_body = request.content.read() or b''
        try:
            post_data = json_loadb(raw_body)
        except JSONDecodeError:
            return get_missing_params_msg('invalid json')

        if 'addresses' not in post_data:
            return get_missing_params_msg('addresses')
        addresses = post_data['addresses']
        assert isinstance(addresses, list)

        # Validate and parse tx_version parameter if provided
        allowed_tx_versions = None
        if 'tx_version' in post_data:
            tx_version_raw = post_data['tx_version']
            # Handle both list/set and single values
            if not isinstance(tx_version_raw, (list, set)):
                tx_version_raw = [tx_version_raw]

            try:
                allowed_tx_versions = set(int(v) for v in tx_version_raw)
            except (ValueError, TypeError) as e:
                return json_dumpb({
                    'success': False,
                    'message': f'Invalid tx_version parameter: must be integer(s), got {e}'
                })

        return self.get_address_history(addresses, post_data.get('hash'), allowed_tx_versions)

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/address_history/

            Expects 'addresses[]' as request args, and 'hash'
            as optional args to be used in pagination

            'addresses[]' is an array of address
            'hash' is the hash of the first tx of the pagination to start the history

            Returns an array of WalletIndex for each address until the maximum number

            E.g. request:

            addresses: ['WYxpdgz11cGGPSdmQPcJVwnLsUu7w5hgjw', 'WSo6BtjdxSSs7FpSzXYgEXwKZ3643K5iSQ']

            In the case where address 'WYxpdgz11cGGPSdmQPcJVwnLsUu7w5hgjw' has 3 txs [tx_id1, tx_id2, tx_id3] and
            address 'WSo6BtjdxSSs7FpSzXYgEXwKZ3643K5iSQ' also has 3 txs [tx_id4, tx_id5, tx_id6].

            Return: {
                'history': [array with 3 txs from first address and 2 txs from second address],
                'has_more': True, indicating that there are more txs for this request
                'first_address': 'WSo6BtjdxSSs7FpSzXYgEXwKZ3643K5iSQ', indicating that the next request should
                                                    start with this address as first element of addresses array
                'first_hash': tx_id6, indicating that the next request should start with this transaction
            }

            So we need to execute one more request to finish getting all transactions. Request:

            addresses: ['WSo6BtjdxSSs7FpSzXYgEXwKZ3643K5iSQ']
            hash: tx_id6

            Important note: different requests may return the same transaction for different addresses.
            We just validate if a transactions was already added in the same request, so e.g. the following case:

            1. tx1 has outputs for addr1 and addr2;
            2. Request to get [addr1, addr2];
            3. First response return txs only for addr1 including tx1;
            4. New request to get the remaining txs for addr1 and the txs for addr2 (including tx1)

            In this case we would return tx1 for both requests because we don't have the txs returned previously.
            We could send in all requests the txs already returned but it does not make much difference now.

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if error_message := self._validate_index(request):
            return error_message

        raw_args = get_args(request)

        if b'addresses[]' not in raw_args:
            return get_missing_params_msg('addresses[]')

        addresses = raw_args[b'addresses[]']

        ref_hash = None
        if b'hash' in raw_args:
            # If hash parameter is in the request, it must be a valid hex
            ref_hash = raw_args[b'hash'][0].decode('utf-8')

        allowed_tx_versions_arg = raw_args.get(b'tx_version[]', None)
        allowed_tx_versions = None
        if allowed_tx_versions_arg is not None:
            try:
                allowed_tx_versions = set([int(tx_version.decode('utf-8')) for tx_version in allowed_tx_versions_arg])
            except ValueError as e:
                return json_dumpb({
                    'success': False,
                    'message': f'Invalid tx_version parameter: {e}'
                })
        return self.get_address_history(
            [address.decode('utf-8') for address in addresses],
            ref_hash,
            allowed_tx_versions
        )

    def _validate_index(self, request: Request) -> bytes | None:
        """Return None if validation is successful (addresses index is enabled), and an error message otherwise."""
        if self.manager.tx_storage.indexes.addresses:
            return None

        self._log.warn(
            'trying to reach address history endpoint, but addresses index is disabled.\n'
            'use `--wallet-index` to enable it'
        )
        request.setResponseCode(503)
        return json_dumpb({'success': False, 'message': 'wallet index is disabled'})

    def get_address_history(self,
                            addresses: list[str],
                            ref_hash: Optional[str],
                            allowed_tx_versions: Optional[set[int]]) -> bytes:
        ref_hash_bytes = None
        if ref_hash:
            try:
                ref_hash_bytes = bytes.fromhex(ref_hash)
            except ValueError:
                # ref_hash is an invalid hex value
                return json_dumpb({
                    'success': False,
                    'message': 'Invalid hash {}'.format(ref_hash)
                })

        addresses_index = self.manager.tx_storage.indexes.addresses

        # Pagination variables
        has_more = False
        first_hash = None
        first_address = None
        total_added = 0
        total_elements = 0

        history = []
        seen: set[bytes] = set()
        for idx, address in enumerate(addresses):
            try:
                decode_address(address)
            except InvalidAddress:
                return json_dumpb({
                    'success': False,
                    'message': 'The address {} is invalid'.format(address)
                })

            # The address index returns an iterable that starts at `tx`.
            if idx == 0:
                ref_tx = None
                if ref_hash_bytes:
                    try:
                        ref_tx = self.manager.tx_storage.get_transaction(ref_hash_bytes)
                    except TransactionDoesNotExist:
                        return json_dumpb({
                            'success': False,
                            'message': 'Hash {} is not a transaction hash.'.format(ref_hash)
                        })
                hashes = addresses_index.get_sorted_from_address(address, ref_tx)
            else:
                hashes = addresses_index.get_sorted_from_address(address)
            did_break = False
            for tx_hash in hashes:
                if total_added == self.max_tx_addresses_history:
                    # If already added the max number of elements possible, then break
                    # I need to add this if at the beginning of the loop to handle the case
                    # when the first tx of the address exceeds the limit, so we must return
                    # that the next request should start in the first tx of this address
                    did_break = True
                    # Saving the first tx hash for the next request
                    first_hash = tx_hash.hex()
                    break

                if tx_hash not in seen:
                    tx = self.manager.tx_storage.get_transaction(tx_hash)
                    if allowed_tx_versions and tx.version not in allowed_tx_versions:
                        # Transaction version is not in the version filter
                        continue

                    tx_elements = len(tx.inputs) + len(tx.outputs)
                    if total_elements + tx_elements > self.max_inputs_outputs_address_history:
                        # If the adition of this tx overcomes the maximum number of inputs and outputs, then break
                        # It's important to validate also the maximum number of inputs and outputs because some txs
                        # are really big and the response payload becomes too big
                        did_break = True
                        # Saving the first tx hash for the next request
                        first_hash = tx_hash.hex()
                        break

                    seen.add(tx_hash)
                    history.append(tx.to_json_extended())
                    total_added += 1
                    total_elements += tx_elements

            if did_break:
                # We stopped in the middle of the txs of this address
                # So we return that we still have more data to send
                has_more = True
                # The hash to start the search and which address this hash belongs
                first_address = address
                break

        data: dict[str, Any] = {
            'success': True,
            'history': history,
            'has_more': has_more,
            'first_hash': first_hash,
            'first_address': first_address
        }
        return json_dumpb(data)


AddressHistoryResource.openapi = {
    '/thin_wallet/address_history': {
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
                    'rate': '6r/s',
                    'burst': 15,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['wallet'],
            'operationId': 'address_history',
            'summary': 'History of some addresses. Important note: different requests (even pagination requests) '
                       'may return the same transaction for different addresses. We just validate if a transactions '
                       'was already added in the same request.',
            'parameters': [
                {
                    'name': 'addresses[]',
                    'in': 'query',
                    'description': 'Stringified array of addresses',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'hash',
                    'in': 'query',
                    'description': 'Hash used to paginate the request.',
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'tx_version[]',
                    'in': 'query',
                    'description': 'List of versions to filter the transactions.',
                    'schema': {
                        'type': 'int'
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
                                        'has_more': True,
                                        'first_hash': '00000299670db5814f69cede8b347f83'
                                                      '0f73985eaa4cd1ce87c9a7c793771332',
                                        'first_address': '1Pz5s5WVL52MK4EwBy9XVQUzWjF2LWWKiS',
                                        'history': [
                                            {
                                                "hash": "00000299670db5814f69cede8b347f83"
                                                        "0f73985eaa4cd1ce87c9a7c793771336",
                                                "timestamp": 1552422415,
                                                "is_voided": False,
                                                'parents': [
                                                    '00000b8792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb5',
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb1'
                                                ],
                                                "inputs": [
                                                    {
                                                        "value": 42500000044,
                                                        "script": "dqkURJPA8tDMJHU8tqv3SiO18ZCLEPaIrA==",
                                                        "decoded": {
                                                            "type": "P2PKH",
                                                            "address": "17Fbx9ouRUD1sd32bp4ptGkmgNzg7p2Krj",
                                                            "timelock": None
                                                            },
                                                        "token": "00",
                                                        "tx": "000002d28696f94f89d639022ae81a1d"
                                                              "870d55d189c27b7161d9cb214ad1c90c",
                                                        "index": 0
                                                        }
                                                    ],
                                                "outputs": [
                                                    {
                                                        "value": 42499999255,
                                                        "script": "dqkU/B6Jbf5OnslsQrvHXQ4WKDTSEGKIrA==",
                                                        "decoded": {
                                                            "type": "P2PKH",
                                                            "address": "1Pz5s5WVL52MK4EwBy9XVQUzWjF2LWWKiS",
                                                            "timelock": None
                                                            },
                                                        "token": "00"
                                                        },
                                                    {
                                                        "value": 789,
                                                        "script": "dqkUrWoWhiP+qPeI/qwfwb5fgnmtd4CIrA==",
                                                        "decoded": {
                                                            "type": "P2PKH",
                                                            "address": "1GovzJvbzLw6x4H2a1hHb529cpEWzh3YRd",
                                                            "timelock": None
                                                            },
                                                        "token": "00"
                                                        }
                                                    ],
                                                "first_block": ("000005af290a55b079014a0be3246479"
                                                                "e84eeb635f02010dbf3e5f3414a85bbb")
                                            }
                                        ]
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid address',
                                    'value': {
                                        'success': False,
                                        'message': 'The address xx is invalid',
                                    }
                                },
                                'error_invalid_tx_version': {
                                    'summary': 'Invalid tx_version parameter',
                                    'value': {
                                        'success': False,
                                        'message': "Invalid tx_version parameter: invalid literal for int() "
                                                   "with base 10: 'INVALID'",
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
