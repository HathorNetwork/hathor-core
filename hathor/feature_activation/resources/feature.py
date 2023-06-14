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

from hathor.api_util import Resource, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction.storage import TransactionStorage
from hathor.utils.api import Response


@register_resource
class FeatureResource(Resource):
    __slots__ = ()

    isLeaf = True

    def __init__(
        self,
        *,
        feature_settings: FeatureSettings,
        feature_service: FeatureService,
        tx_storage: TransactionStorage
    ) -> None:
        super().__init__()
        self._feature_settings = feature_settings
        self._feature_service = feature_service
        self.tx_storage = tx_storage

    def render_GET(self, request: Request) -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        best_block = self.tx_storage.get_best_block()
        bit_counts = best_block.get_feature_activation_bit_counts()
        features = []

        for feature, criteria in self._feature_settings.features.items():
            state = self._feature_service.get_state(block=best_block, feature=feature)
            threshold_count = criteria.get_threshold(self._feature_settings)
            threshold_percentage = threshold_count / self._feature_settings.evaluation_interval
            acceptance_percentage = None

            if state is FeatureState.STARTED:
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
                activate_on_timeout=criteria.activate_on_timeout,
                version=criteria.version
            )

            features.append(feature_response)

        response = GetFeaturesResponse(
            block_hash=best_block.hash_hex,
            block_height=best_block.get_height(),
            features=features
        )

        return response.json_dumpb()


class GetFeatureResponse(Response, use_enum_values=True):
    name: Feature
    state: str
    acceptance: Optional[float]
    threshold: float
    start_height: int
    minimum_activation_height: int
    timeout_height: int
    activate_on_timeout: bool
    version: str


class GetFeaturesResponse(Response):
    block_hash: str
    block_height: int
    features: list[GetFeatureResponse]


FeatureResource.openapi = {
    '/feature': {
        'x-visibility': 'private',
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
                                            'activate_on_timeout': False,
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
                                            'activate_on_timeout': False,
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
