import json
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Dict

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
class RichestAddressesResource(resource.Resource):
    """ Implements a web server API to return the address balance

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def has_address(self, output: 'TxOutput', requested_address: str) -> bool:
        """ Check if output address is the same as requested_address
        """
        if output.is_token_authority():
            return False

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

        balances = {}
        addresses = wallet_index.index.keys()

        MAX_QUANTITY = 30
        MIN_BALANCE = 999999999999999999
        MIN_BALANCE_ADDRESS = ''

        for address in addresses:
            balance = 0
            tx_hashes = wallet_index.get_from_address(address)
            for tx_hash in tx_hashes:
                tx = self.manager.tx_storage.get_transaction(tx_hash)
                meta = tx.get_metadata(force_reload=True)
                if not meta.voided_by:
                    # We consider the spent/received values only if is not voided by
                    for tx_input in tx.inputs:
                        tx2 = self.manager.tx_storage.get_transaction(tx_input.tx_id)
                        tx2_output = tx2.outputs[tx_input.index]
                        if self.has_address(tx2_output, address):
                            # We just consider the address that was requested
                            if tx2_output.token_data == 0:
                                balance -= tx2_output.value

                    for tx_output in tx.outputs:
                        if self.has_address(tx_output, address):
                            # We just consider the address that was requested
                            if tx_output.token_data == 0:
                                balance += tx_output.value

            if len(balances.keys()) < MAX_QUANTITY:
                balances[address] = balance

                if balance < MIN_BALANCE:
                    MIN_BALANCE = balance
                    MIN_BALANCE_ADDRESS = address
            elif balance > MIN_BALANCE:
                balances[address] = balance
                del balances[MIN_BALANCE_ADDRESS]

                new_min = min(balances.items(), key=lambda x: x[1]) 
                MIN_BALANCE = new_min[1]
                MIN_BALANCE_ADDRESS = new_min[0]

        data = {
            'success': True,
            'richest_addresses': [(k, balances[k]) for k in sorted(balances, key=balances.get, reverse=True)],
        }
        return json.dumps(data, indent=4).encode('utf-8')
