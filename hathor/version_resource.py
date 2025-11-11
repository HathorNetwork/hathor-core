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

import hathor
from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.feature_activation.feature_service import FeatureService
from hathor.manager import HathorManager
from hathor.nanocontracts.utils import is_nano_active
from hathor.util import json_dumpb


@register_resource
class VersionResource(Resource):
    """ Implements a web server API with POST to return the api version and some configuration

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager, feature_service: FeatureService) -> None:
        # Important to have the manager so we can have access to min_tx_weight_coefficient
        super().__init__()
        self._settings = get_global_settings()
        self.manager = manager
        self.feature_service = feature_service

    def render_GET(self, request):
        """ GET request for /version/ that returns the API version

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        best_block = self.manager.tx_storage.get_best_block()
        nano_contracts_enabled = is_nano_active(
            settings=self._settings, block=best_block, feature_service=self.feature_service
        )

        data = {
            'version': hathor.__version__,
            'network': self.manager.network,
            'nano_contracts_enabled': nano_contracts_enabled,
            'min_weight': self._settings.MIN_TX_WEIGHT,  # DEPRECATED
            'min_tx_weight': self._settings.MIN_TX_WEIGHT,
            'min_tx_weight_coefficient': self._settings.MIN_TX_WEIGHT_COEFFICIENT,
            'min_tx_weight_k': self._settings.MIN_TX_WEIGHT_K,
            'token_deposit_percentage': self._settings.TOKEN_DEPOSIT_PERCENTAGE,
            'reward_spend_min_blocks': self._settings.REWARD_SPEND_MIN_BLOCKS,
            'max_number_inputs': self._settings.MAX_NUM_INPUTS,
            'max_number_outputs': self._settings.MAX_NUM_OUTPUTS,
            'decimal_places': self._settings.DECIMAL_PLACES,
            'genesis_block_hash': self._settings.GENESIS_BLOCK_HASH.hex(),
            'genesis_tx1_hash': self._settings.GENESIS_TX1_HASH.hex(),
            'genesis_tx2_hash': self._settings.GENESIS_TX2_HASH.hex(),
            'native_token': dict(
                name=self._settings.NATIVE_TOKEN_NAME,
                symbol=self._settings.NATIVE_TOKEN_SYMBOL,
            ),
        }
        return json_dumpb(data)


VersionResource.openapi = {
    '/version': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '360r/s',
                    'burst': 360,
                    'delay': 180
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
            'operationId': 'version',
            'summary': 'Hathor version',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'version': '0.16.0-beta',
                                        'network': 'testnet-bravo',
                                        'min_weight': 14,
                                        'min_tx_weight': 14,
                                        'min_tx_weight_coefficient': 1.6,
                                        'min_tx_weight_k': 100,
                                        'token_deposit_percentage': 0.01,
                                        'reward_spend_min_blocks': 300,
                                        'max_number_inputs': 256,
                                        'max_number_outputs': 256,
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
