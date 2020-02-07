import json
from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import get_missing_params_msg, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.transaction.scripts import parse_address_script
from hathor.wallet.exceptions import InvalidAddress

if TYPE_CHECKING:
    from hathor.transaction import TxOutput

settings = HathorSettings()


@register_resource
class AddressBalanceResource(resource.Resource):
    """ Implements a web server API to return the address balance

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def should_add_value(self, output: 'TxOutput', requested_address: str) -> bool:
        """ Check if output address is the same as requested_address
        """
        script_type_out = parse_address_script(output.script)
        if script_type_out:
            if script_type_out.address == requested_address:
                return True
        return False

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/address_balance/
            Expects 'address' as request args

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        wallet_index = self.manager.tx_storage.wallet_index
        tokens_index = self.manager.tx_storage.tokens_index

        if not wallet_index or not tokens_index:
            request.setResponseCode(503)
            return json.dumps({'success': False}, indent=4).encode('utf-8')

        if b'address' in request.args:
            requested_address = request.args[b'address'][0].decode('utf-8')
        else:
            return get_missing_params_msg('address')

        try:
            # Check if address is valid
            decode_address(requested_address)
        except InvalidAddress:
            return json.dumps({
                'success': False,
                'message': 'Invalid \'address\' parameter'
            }).encode('utf-8')

        tokens_data = {}
        # Shouldn't use defaultdict(int) because we also have strings on this dict
        start_dict = {'received': 0, 'spent': 0}
        tx_hashes = wallet_index.get_from_address(requested_address)
        for tx_hash in tx_hashes:
            tx = self.manager.tx_storage.get_transaction(tx_hash)
            meta = tx.get_metadata(force_reload=True)
            if not meta.voided_by:
                # We consider the spent/received values only if is not voided by
                for tx_input in tx.inputs:
                    tx2 = self.manager.tx_storage.get_transaction(tx_input.tx_id)
                    tx2_output = tx2.outputs[tx_input.index]
                    if self.should_add_value(tx2_output, requested_address):
                        # We just consider the address that was requested
                        token_uid = tx2.get_token_uid(tx2_output.get_token_index())
                        token_uid_hex = token_uid.hex()
                        if token_uid_hex not in tokens_data:
                            tokens_data[token_uid_hex] = start_dict.copy()
                        tokens_data[token_uid_hex]['spent'] += tx2_output.value

                for tx_output in tx.outputs:
                    if self.should_add_value(tx_output, requested_address):
                        # We just consider the address that was requested
                        token_uid = tx.get_token_uid(tx_output.get_token_index())
                        token_uid_hex = token_uid.hex()
                        if token_uid_hex not in tokens_data:
                            tokens_data[token_uid_hex] = start_dict.copy()
                        tokens_data[token_uid_hex]['received'] += tx_output.value

        for token_uid_hex in tokens_data.keys():
            token_uid = bytes.fromhex(token_uid_hex)
            if token_uid == settings.HATHOR_TOKEN_UID:
                tokens_data[token_uid_hex]['name'] = settings.HATHOR_TOKEN_NAME
                tokens_data[token_uid_hex]['symbol'] = settings.HATHOR_TOKEN_SYMBOL
            else:
                try:
                    token_info = tokens_index.get_token_info(token_uid)
                    tokens_data[token_uid_hex]['name'] = token_info.name
                    tokens_data[token_uid_hex]['symbol'] = token_info.symbol
                except KeyError:
                    # Should never get here because this token appears in our wallet index
                    # But better than get a 500 error
                    return json.dumps({'success': False, 'message': 'Unknown token'}, indent=4).encode('utf-8')
        data = {
            'success': True,
            'quantity': len(tx_hashes),
            'tokens_data': tokens_data
        }
        return json.dumps(data, indent=4).encode('utf-8')


AddressBalanceResource.openapi = {
    '/thin_wallet/address_balance': {
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
            'operationId': 'address_balance',
            'summary': 'Balance of an address',
            'parameters': [
                {
                    'name': 'address',
                    'in': 'query',
                    'description': 'Address to get balance',
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
                                        'quantity': 5,
                                        'tokens_data': {
                                            '00': {
                                                'name': 'Hathor',
                                                'symbol': 'HTR',
                                                'received': 1000,
                                                'spent': 800,
                                            },
                                            '00001241240': {
                                                'name': 'NewCoin',
                                                'symbol': 'NCN',
                                                'received': 100,
                                                'spent': 20,
                                            },
                                        }
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid address',
                                    'value': {
                                        'success': False,
                                        'message': 'The address xx is invalid',
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