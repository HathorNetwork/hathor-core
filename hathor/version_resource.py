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

from pydantic import Field

import hathor
from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api.schemas import ResponseModel
from hathor.api_util import Resource, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.utils import Features
from hathor.manager import HathorManager
from hathor.types import BlockId, TransactionId
from hathor.utils.pydantic import Hex


class NativeTokenInfo(ResponseModel):
    """Information about the native token."""
    name: str = Field(description="Native token name")
    symbol: str = Field(description="Native token symbol")


class VersionResponse(ResponseModel):
    """Response model for the /version endpoint."""
    version: str = Field(description="Hathor core version")
    network: str = Field(description="Network name (e.g., mainnet, testnet)")
    nano_contracts_enabled: bool = Field(description="Whether nano contracts are enabled")
    min_weight: int = Field(description="Minimum transaction weight (DEPRECATED)")
    min_tx_weight: int = Field(description="Minimum transaction weight")
    min_tx_weight_coefficient: float = Field(description="Minimum transaction weight coefficient")
    min_tx_weight_k: float = Field(description="Minimum transaction weight k constant")
    token_deposit_percentage: float = Field(description="Token deposit percentage")
    reward_spend_min_blocks: int = Field(description="Minimum blocks before reward can be spent")
    max_number_inputs: int = Field(description="Maximum number of inputs per transaction")
    max_number_outputs: int = Field(description="Maximum number of outputs per transaction")
    decimal_places: int = Field(description="Number of decimal places for token amounts")
    genesis_block_hash: Hex[BlockId] = Field(description="Genesis block hash in hex")
    genesis_tx1_hash: Hex[TransactionId] = Field(description="Genesis transaction 1 hash in hex")
    genesis_tx2_hash: Hex[TransactionId] = Field(description="Genesis transaction 2 hash in hex")
    native_token: NativeTokenInfo = Field(description="Native token information")


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

    @api_endpoint(
        path='/version',
        method='GET',
        operation_id='version',
        summary='Hathor version',
        description='Returns the API version and network configuration parameters.',
        tags=['general'],
        visibility='public',
        rate_limit_global=[{'rate': '360r/s', 'burst': 360, 'delay': 180}],
        rate_limit_per_ip=[{'rate': '3r/s', 'burst': 10, 'delay': 3}],
        response_model=VersionResponse,
    )
    def render_GET(self, request):
        """ GET request for /version/ that returns the API version

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        best_block = self.manager.tx_storage.get_best_block()
        features = Features.from_vertex(
            settings=self._settings, vertex=best_block, feature_service=self.feature_service
        )
        nano_contracts_enabled = features.nanocontracts

        response = VersionResponse(
            version=hathor.__version__,
            network=self.manager.network,
            nano_contracts_enabled=nano_contracts_enabled,
            min_weight=self._settings.MIN_TX_WEIGHT,
            min_tx_weight=self._settings.MIN_TX_WEIGHT,
            min_tx_weight_coefficient=self._settings.MIN_TX_WEIGHT_COEFFICIENT,
            min_tx_weight_k=self._settings.MIN_TX_WEIGHT_K,
            token_deposit_percentage=self._settings.TOKEN_DEPOSIT_PERCENTAGE,
            reward_spend_min_blocks=self._settings.REWARD_SPEND_MIN_BLOCKS,
            max_number_inputs=self._settings.MAX_NUM_INPUTS,
            max_number_outputs=self._settings.MAX_NUM_OUTPUTS,
            decimal_places=self._settings.DECIMAL_PLACES,
            genesis_block_hash=self._settings.GENESIS_BLOCK_HASH,
            genesis_tx1_hash=self._settings.GENESIS_TX1_HASH,
            genesis_tx2_hash=self._settings.GENESIS_TX2_HASH,
            native_token=NativeTokenInfo(
                name=self._settings.NATIVE_TOKEN_NAME,
                symbol=self._settings.NATIVE_TOKEN_SYMBOL,
            ),
        )
        return response.json_dumpb()
