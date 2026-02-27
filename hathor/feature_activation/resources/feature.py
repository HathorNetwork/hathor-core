#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from typing import Optional, Union

from pydantic import ConfigDict, Field
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api.schemas import ErrorResponse, OpenAPIExample, ResponseModel
from hathor.api_util import Resource
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage
from hathor.types import BlockId
from hathor.utils.api import QueryParams
from hathor.utils.pydantic import Hex


class GetBlockFeaturesParams(QueryParams):
    """Query parameters for the /feature endpoint."""
    block: Hex[BlockId] | None = Field(
        default=None,
        description="Block hash to query feature states for"
    )


class GetBlockFeatureResponse(ResponseModel):
    """Response model for a single feature's state in a block."""
    model_config = ConfigDict(use_enum_values=True)

    bit: int = Field(description="Signal bit for this feature")
    signal: int = Field(description="Signal value in the block")
    feature: Feature = Field(description="Feature identifier")
    feature_state: str = Field(description="Current state of the feature")


class GetBlockFeaturesResponse(ResponseModel):
    """Response model for all features' states in a block."""
    signal_bits: list[GetBlockFeatureResponse] = Field(description="List of feature signal states")


class GetFeatureResponse(ResponseModel):
    """Response model for a single feature's activation info."""
    model_config = ConfigDict(use_enum_values=True)

    name: Feature = Field(description="Feature identifier")
    state: str = Field(description="Current activation state")
    acceptance: Optional[float] = Field(description="Current acceptance percentage (if in signaling state)")
    threshold: float = Field(description="Required threshold percentage for activation")
    start_height: int = Field(description="Block height when signaling starts")
    minimum_activation_height: int = Field(description="Minimum height for activation")
    timeout_height: int = Field(description="Block height when signaling times out")
    lock_in_on_timeout: bool = Field(description="Whether to lock in on timeout")
    version: str = Field(description="Feature version string")


class GetFeaturesResponse(ResponseModel):
    """Response model for all features' activation info."""
    block_hash: Hex[BlockId] = Field(description="Best block hash")
    block_height: int = Field(description="Best block height")
    features: list[GetFeatureResponse] = Field(description="List of feature activation info")


GetFeaturesResponse.openapi_examples = {
    'success': OpenAPIExample(
        summary='Feature activation info',
        value=GetFeaturesResponse(
            block_hash=BlockId(bytes.fromhex('00000000083580e5b299e9cb271fd5977103897e8640fcd5498767b6cefba6f5')),
            block_height=123,
            features=[
                GetFeatureResponse(
                    name=Feature.NOP_FEATURE_1,
                    state='ACTIVE',
                    acceptance=None,
                    threshold=0.75,
                    start_height=0,
                    minimum_activation_height=0,
                    timeout_height=100,
                    lock_in_on_timeout=False,
                    version='0.1.0',
                ),
                GetFeatureResponse(
                    name=Feature.NOP_FEATURE_2,
                    state='STARTED',
                    acceptance=0.25,
                    threshold=0.5,
                    start_height=200,
                    minimum_activation_height=0,
                    timeout_height=300,
                    lock_in_on_timeout=False,
                    version='0.2.0',
                ),
            ],
        ),
    ),
}


@register_resource
class FeatureResource(Resource):
    __slots__ = ()

    isLeaf = True

    def __init__(
        self,
        *,
        settings: HathorSettings,
        feature_service: FeatureService,
        tx_storage: TransactionStorage
    ) -> None:
        super().__init__()
        self._feature_settings = settings.FEATURE_ACTIVATION
        self._feature_service = feature_service
        self.tx_storage = tx_storage

    @api_endpoint(
        path='/feature',
        method='GET',
        operation_id='feature',
        summary='Feature Activation',
        description='Returns information about features in the Feature Activation process.',
        tags=['feature'],
        visibility='public',
        rate_limit_global=[{'rate': '50r/s', 'burst': 100, 'delay': 50}],
        rate_limit_per_ip=[{'rate': '1r/s', 'burst': 10, 'delay': 3}],
        query_params_model=GetBlockFeaturesParams,
        response_model=Union[GetFeaturesResponse, GetBlockFeaturesResponse, ErrorResponse],
    )
    def render_GET(self, request: Request, *, params: GetBlockFeaturesParams) -> ResponseModel:
        if params.block is not None:
            return self._get_block_features(params)

        return self._get_features()

    def _get_block_features(self, params: GetBlockFeaturesParams) -> ResponseModel:
        assert params.block is not None
        block = self.tx_storage.get_transaction(params.block)

        if not isinstance(block, Block):
            return ErrorResponse(error=f"Hash '{params.block.hex()}' is not a Block.")

        signal_bits = []
        feature_infos = self._feature_service.get_feature_infos(vertex=block)

        for feature, feature_info in feature_infos.items():
            if feature_info.state not in FeatureState.get_signaling_states():
                continue

            block_feature = GetBlockFeatureResponse(
                bit=feature_info.criteria.bit,
                signal=block.get_feature_activation_bit_value(feature_info.criteria.bit),
                feature=feature,
                feature_state=feature_info.state.name
            )

            signal_bits.append(block_feature)

        return GetBlockFeaturesResponse(signal_bits=signal_bits)

    def _get_features(self) -> GetFeaturesResponse:
        best_block = self.tx_storage.get_best_block()
        bit_counts = best_block.static_metadata.feature_activation_bit_counts
        feature_infos = self._feature_service.get_feature_infos(vertex=best_block)
        features = []

        for feature, feature_info in feature_infos.items():
            state = feature_info.state
            criteria = feature_info.criteria
            threshold_count = criteria.get_threshold(self._feature_settings)
            threshold_percentage = threshold_count / self._feature_settings.evaluation_interval
            acceptance_percentage = None

            if state in [FeatureState.STARTED, FeatureState.MUST_SIGNAL]:
                acceptance_count = bit_counts[criteria.bit]
                acceptance_percentage = acceptance_count / self._feature_settings.evaluation_interval

            feature_response = GetFeatureResponse(
                name=feature,
                state=state.name,
                acceptance=acceptance_percentage,
                threshold=threshold_percentage,
                start_height=criteria.start_height,
                minimum_activation_height=criteria.minimum_activation_height,
                timeout_height=criteria.timeout_height,
                lock_in_on_timeout=criteria.lock_in_on_timeout,
                version=criteria.version
            )

            features.append(feature_response)

        return GetFeaturesResponse(
            block_hash=BlockId(best_block.hash),
            block_height=best_block.get_height(),
            features=features
        )
