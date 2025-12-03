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

from typing import Optional

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage
from hathor.utils.api import ErrorResponse, QueryParams, Response


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

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if request.args:
            return self.get_block_features(request)

        return self.get_features()

    def get_block_features(self, request: Request) -> bytes:
        params = GetBlockFeaturesParams.from_request(request)

        if isinstance(params, ErrorResponse):
            return params.json_dumpb()

        block_hash = bytes.fromhex(params.block)
        block = self.tx_storage.get_transaction(block_hash)

        if not isinstance(block, Block):
            error = ErrorResponse(error=f"Hash '{params.block}' is not a Block.")
            return error.json_dumpb()

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

        response = GetBlockFeaturesResponse(signal_bits=signal_bits)

        return response.json_dumpb()

    def get_features(self) -> bytes:
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

        response = GetFeaturesResponse(
            block_hash=best_block.hash_hex,
            block_height=best_block.get_height(),
            features=features
        )

        return response.json_dumpb()


class GetBlockFeaturesParams(QueryParams):
    block: str


class GetBlockFeatureResponse(Response, use_enum_values=True):
    bit: int
    signal: int
    feature: Feature
    feature_state: str


class GetBlockFeaturesResponse(Response):
    signal_bits: list[GetBlockFeatureResponse]


class GetFeatureResponse(Response, use_enum_values=True):
    name: Feature
    state: str
    acceptance: Optional[float]
    threshold: float
    start_height: int
    minimum_activation_height: int
    timeout_height: int
    lock_in_on_timeout: bool
    version: str


class GetFeaturesResponse(Response):
    block_hash: str
    block_height: int
    features: list[GetFeatureResponse]


FeatureResource.openapi = {
    '/feature': {
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
                    'rate': '1r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'operationId': 'feature',
            'summary': 'Feature Activation',
            'description': 'Returns information about features in the Feature Activation process',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'block_hash': '00000000083580e5b299e9cb271fd5977103897e8640fcd5498767b6cefba6f5',
                                    'block_height': 123,
                                    'features': [
                                        {
                                            'name': 'NOP_FEATURE_1',
                                            'state': 'ACTIVE',
                                            'acceptance': None,
                                            'threshold': 0.75,
                                            'start_height': 0,
                                            'minimum_activation_height': 0,
                                            'timeout_height': 100,
                                            'lock_in_on_timeout': False,
                                            'version': '0.1.0'
                                        },
                                        {
                                            'name': 'NOP_FEATURE_2',
                                            'state': 'STARTED',
                                            'acceptance': 0.25,
                                            'threshold': 0.5,
                                            'start_height': 200,
                                            'minimum_activation_height': 0,
                                            'timeout_height': 300,
                                            'lock_in_on_timeout': False,
                                            'version': '0.2.0'
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
