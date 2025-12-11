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

from structlog import get_logger
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import (
    Resource,
    get_args,
    get_missing_params_msg,
    parse_args,
    parse_int,
    set_cors,
    validate_tx_hash,
)
from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Block
from hathor.transaction.base_transaction import BaseTransaction, TxVersion
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.util import json_dumpb

GET_LIST_ARGS = ['count', 'type']

logger = get_logger()


def update_serialized_tokens_array(tx: BaseTransaction, serialized: dict[str, Any]) -> None:
    """ A token creation tx to_json does not add its hash to the array of tokens
        We manually have to add it here to make it equal to the other transactions
    """
    if TxVersion(tx.version) == TxVersion.TOKEN_CREATION_TRANSACTION:
        # Token creation tx does not add tokens array in to_json method but we need it in this API
        assert isinstance(tx, TokenCreationTransaction)
        serialized['tokens'] = [h.hex() for h in tx.tokens]


def get_tx_extra_data(
    tx: BaseTransaction,
    *,
    detail_tokens: bool = True,
    force_reload_metadata: bool = True,
) -> dict[str, Any]:
    """ Get the data of a tx to be returned to the frontend
        Returns success, tx serializes, metadata and spent outputs
    """
    assert tx.storage is not None
    assert tx.storage.indexes is not None

    settings = get_global_settings()
    serialized = tx.to_json(decode_script=True)
    serialized['raw'] = tx.get_struct().hex()
    serialized['nonce'] = str(tx.nonce)

    # Update tokens array
    update_serialized_tokens_array(tx, serialized)
    meta = tx.get_metadata(force_reload=force_reload_metadata)
    # To get the updated accumulated weight just need to call the
    # TransactionAccumulatedWeightResource (/transaction_acc_weight)

    if isinstance(tx, Block):
        # For blocks we need to add the height
        serialized['height'] = tx.static_metadata.height

    # In the metadata we have the spent_outputs, that are the txs that spent the outputs for each index
    # However we need to send also which one of them is not voided
    spent_outputs = {}
    for index, spent_set in meta.spent_outputs.items():
        for spent in spent_set:
            if tx.storage:
                spent_tx = tx.storage.get_transaction(spent)
                spent_meta = spent_tx.get_metadata()
                if not spent_meta.voided_by:
                    spent_outputs[index] = spent_tx.hash_hex
                    break

    # Maps the token uid to the token_data value
    token_uid_map: dict[bytes, int] = {settings.HATHOR_TOKEN_UID: 0}

    # Sending also output information for each input
    inputs = []
    for index, tx_in in enumerate(tx.inputs):
        if tx.storage:
            tx2 = tx.storage.get_transaction(tx_in.tx_id)
            tx2_out = tx2.outputs[tx_in.index]
            output = tx2_out.to_json(decode_script=True)
            output['tx_id'] = tx2.hash_hex
            output['index'] = tx_in.index

            # We need to get the token_data from the current tx, and not the tx being spent
            token_uid = tx2.get_token_uid(tx2_out.get_token_index())
            if token_uid not in token_uid_map:
                for idx, uid in enumerate(serialized['tokens']):
                    # If we find the uid in the serialized tokens
                    # we set the token_data as the array index plus 1
                    if token_uid.hex() == uid:
                        token_uid_map[token_uid] = idx + 1
                        break
                else:
                    # This is the case when the token from the input does not appear in the outputs
                    # This case can happen when we have a full melt, so all tokens from the inputs are destroyed
                    # So we manually add this token to the array and set the token_data properly
                    serialized['tokens'].append(token_uid.hex())
                    token_uid_map[token_uid] = len(serialized['tokens'])

            token_data = token_uid_map[token_uid]
            if tx2_out.is_token_authority():
                token_data = token_data | tx2_out.TOKEN_AUTHORITY_MASK
            output['decoded']['token_data'] = token_data
            output['token_data'] = token_data
            inputs.append(output)

    serialized['inputs'] = inputs

    if detail_tokens:
        detailed_tokens = []
        for token_uid_hex in serialized['tokens']:
            tokens_index = tx.storage.indexes.tokens
            assert tokens_index is not None
            token_info = tokens_index.get_token_info(bytes.fromhex(token_uid_hex))
            detailed_tokens.append({
                'uid': token_uid_hex,
                'name': token_info.get_name(),
                'symbol': token_info.get_symbol(),
            })

        serialized['tokens'] = detailed_tokens

    result = {
        'success': True,
        'tx': serialized,
        'meta': meta.to_json_extended(tx.storage),
        'spent_outputs': spent_outputs,
    }

    return result


@register_resource
class TransactionResource(Resource):
    """ Implements a web server API to return the tx.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self._log = logger.new()
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
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

        raw_args = get_args(request)
        if b'id' in raw_args:
            # Get one tx
            data = self.get_one_tx(request)
        else:
            # Get all tx
            data = self.get_list_tx(request)

        return data

    def get_one_tx(self, request: Request) -> bytes:
        """ Get 'id' (hash) from request.args
            Returns the tx with this hash or {'success': False} if hash is invalid or tx does not exist
        """
        if error_message := self._validate_index(request):
            return error_message

        raw_args = get_args(request)
        requested_hash = raw_args[b'id'][0].decode('utf-8')
        success, message = validate_tx_hash(requested_hash, self.manager.tx_storage)
        if not success:
            data = {'success': False, 'message': message}
        else:
            hash_bytes = bytes.fromhex(requested_hash)
            tx = self.manager.tx_storage.get_transaction(hash_bytes)
            tx.storage = self.manager.tx_storage

            data = get_tx_extra_data(tx)

            # Check for optional log/event parameters and add them if requested
            include_nc_logs = raw_args.get(b'include_nc_logs', [b'false'])[0].decode('utf-8').lower() == 'true'
            include_nc_events = raw_args.get(b'include_nc_events', [b'false'])[0].decode('utf-8').lower() == 'true'

            if include_nc_logs or include_nc_events:
                if include_nc_logs:
                    self.manager.vertex_json_serializer._add_nc_logs_to_dict(tx, data)
                if include_nc_events:
                    self.manager.vertex_json_serializer._add_nc_events_to_dict(tx, data)

            # Add decoded nano contract arguments if applicable
            self.manager.vertex_json_serializer._add_nc_args_decoded(tx, data)

        return json_dumpb(data)

    def _validate_index(self, request: Request) -> bytes | None:
        """Return None if validation is successful (tokens index is enabled), and an error message otherwise."""
        if self.manager.tx_storage.indexes.tokens:
            return None

        self._log.warn(
            'trying to reach transaction endpoint, but tokens index is disabled.\n'
            'use `--wallet-index` to enable it'
        )
        request.setResponseCode(503)
        return json_dumpb({'success': False, 'message': 'wallet index is disabled'})

    def get_list_tx(self, request):
        """ Get parameter from request.args and return list of blocks/txs

            'type': 'block' or 'tx', to indicate if we should return a list of blocks or tx
            'count': int, to indicate the quantity of elements we should return
            'hash': string, the hash reference we are in the pagination
            'timestamp': int, the timestamp reference we are in the pagination
            'page': 'previous' or 'next', to indicate if the user wants after or before the hash reference
        """
        settings = get_global_settings()
        raw_args = get_args(request)
        parsed = parse_args(raw_args, GET_LIST_ARGS)
        if not parsed['success']:
            return get_missing_params_msg(parsed['missing'])

        args = parsed['args']
        error = None

        try:
            count = parse_int(args['count'], cap=settings.MAX_TX_COUNT)
        except ValueError as e:
            error = {
                'success': False,
                'message': f'Failed to parse \'count\': {e}'
            }

        type_tx = args['type']
        if type_tx != 'tx' and type_tx != 'block':
            error = {'success': False, 'message': 'Invalid \'type\' parameter, expected \'block\' or \'tx\''}

        if error:
            return json_dumpb(error)

        ref_hash = None
        page = ''
        if b'hash' in raw_args:
            ref_hash = raw_args[b'hash'][0].decode('utf-8')

            parsed = parse_args(raw_args, ['timestamp', 'page'])
            if not parsed['success']:
                return get_missing_params_msg(parsed['missing'])

            try:
                ref_timestamp = parse_int(parsed['args']['timestamp'])
            except ValueError as e:
                return json_dumpb({
                    'success': False,
                    'message': f'Failed to parse \'timestamp\': {e}'
                })

            page = parsed['args']['page']
            if page != 'previous' and page != 'next':
                return json_dumpb({
                    'success': False,
                    'message': 'Invalid \'page\' parameter, expected \'previous\' or \'next\''
                })

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

        serialized = [element.to_json_extended() for element in elements]

        data = {'transactions': serialized, 'has_more': has_more}
        return json_dumpb(data)


TransactionResource.openapi = {
    '/transaction': {
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
                },
                {
                    'name': 'include_nc_logs',
                    'in': 'query',
                    'description': 'Include nano contract execution logs for nano contract transactions. '
                                   'Default is false.',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
                    }
                },
                {
                    'name': 'include_nc_events',
                    'in': 'query',
                    'description': 'Include nano contract events emitted during execution for nano contract '
                                   'transactions. Default is false.',
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
                                    'summary': 'One success',
                                    'value': {
                                        'tx': {
                                            'hash': '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            'nonce': '17076',
                                            'timestamp': 1539271482,
                                            'version': 1,
                                            'weight': 14.0,
                                            'parents': [],
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
                                            'outputs': [],
                                            'tokens': []
                                        },
                                        'meta': {
                                            'hash': '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            'spent_outputs': [
                                                ['0', [
                                                    '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22e'
                                                ]],
                                                ['1', [
                                                    '00002b3ce4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22e'
                                                ]]
                                            ],
                                            'received_by': [],
                                            'children': [
                                                '00002b3ee4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22d'
                                            ],
                                            'conflict_with': [],
                                            'voided_by': [],
                                            'twins': [],
                                            'accumulated_weight': '1024',
                                            'first_block': None
                                        },
                                        'spent_outputs': {
                                            0: '00002b3ce4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22e'
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
                                                'tx_id': ('00000257054251161adff5899a451ae9'
                                                          '74ac62ca44a7a31179eec5750b0ea406'),
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
                                                'height': 12345,
                                                'first_block': None
                                            },
                                            {
                                                'tx_id': ('00000b8792cb13e8adb51cc7d866541f'
                                                          'c29b532e8dec95ae4661cf3da4d42cb4'),
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
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
