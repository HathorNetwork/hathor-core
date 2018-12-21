from twisted.web import resource
from hathor.api_util import set_cors, get_missing_params_msg
from hathor.transaction import Transaction
from hathor.transaction.scripts import NanoContractMatchValues, NanoContractMatchInterval

import json
import struct
import re


class NanoContractDecodeResource(resource.Resource):
    """ Implements a web server API that receives hex form of a tx and returns decoded value

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request /wallet/nano-contract/decode/ that returns the tx decoded, if success

        Expects 'hex_tx' as GET parameter

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if b'hex_tx' in request.args:
            requested_decode = request.args[b'hex_tx'][0].decode('utf-8')
        else:
            return get_missing_params_msg('hex_tx')

        pattern = r'[a-fA-F\d]+'
        if re.match(pattern, requested_decode) and len(requested_decode) % 2 == 0:
            tx_bytes = bytes.fromhex(requested_decode)

            try:
                tx = Transaction.create_from_struct(tx_bytes)
            except struct.error:
                data = {'success': False}

            outputs = []
            nano_contract = None
            for _output in tx.outputs:
                _nano_contract = (NanoContractMatchValues.parse_script(_output.script) or
                                  NanoContractMatchInterval.parse_script(_output.script))
                if _nano_contract:
                    nano_contract = _nano_contract.to_human_readable()
                    nano_contract['value'] = _output.value
                    continue
                else:
                    outputs.append(_output.to_human_readable())

            my_inputs, other_inputs = self.manager.wallet.separate_inputs(tx.inputs)

            my_inputs = [_in.to_human_readable() for _in in my_inputs]
            other_inputs = [_in.to_human_readable() for _in in other_inputs]

            data = {
                'success': True,
                'nano_contract': nano_contract,
                'outputs': outputs,
                'my_inputs': my_inputs,
                'other_inputs': other_inputs
            }

        else:
            data = {'success': False}
        return json.dumps(data).encode('utf-8')
