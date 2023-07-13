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

from structlog import get_logger

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage

logger = get_logger()

# TODO: SIGNALING_STATES = {FeatureState.STARTED, FeatureState.MUST_SIGNAL, FeatureState.LOCKED_IN}
SIGNALING_STATES = {FeatureState.STARTED}


class BitSignalingService:
    __slots__ = (
        '_log',
        '_feature_settings',
        '_feature_service',
        '_tx_storage',
        '_support_features',
        '_not_support_features'
    )

    def __init__(
        self,
        *,
        feature_settings: FeatureSettings,
        feature_service: FeatureService,
        tx_storage: TransactionStorage,
        support_features: set[Feature],
        not_support_features: set[Feature]
    ) -> None:
        self._log = logger.new()
        self._feature_settings = feature_settings
        self._feature_service = feature_service
        self._tx_storage = tx_storage
        self._support_features = support_features
        self._not_support_features = not_support_features

    def get_signal_bits(self, block: Block) -> int:
        signaling_features = self._get_signaling_features(block)

        self._validate_support_intersection()
        self._validate_non_signaling_features(set(signaling_features.keys()))

        signal_bits = 0

        for feature, criteria in signaling_features.items():
            bit_index = criteria.bit
            default_enable_bit = criteria.signal_support_by_default
            support = feature in self._support_features
            not_support = feature in self._not_support_features
            enable_bit = (default_enable_bit or support) and not not_support

            # TODO: Log the reason for each signal, either default or set by user.
            if enable_bit:
                self._log.info(f'Enabling support signal for feature "{feature.value}".')
            else:
                self._log.info(f'Disabling support signal for feature "{feature.value}".')

            signal_bits |= int(enable_bit) << bit_index

        self._log.info(f'Configured signal bits: {bin(signal_bits)[2:]}')

        return signal_bits

    def _get_signaling_features(self, block: Block) -> dict[Feature, Criteria]:
        feature_descriptions = self._feature_service.get_bits_description(block=block)
        currently_signaling_features = {
            feature: description.criteria
            for feature, description in feature_descriptions.items()
            if description.state in SIGNALING_STATES
        }

        assert len(currently_signaling_features) <= self._feature_settings.max_signal_bits, (
            'Invalid state. Signaling more features than the allowed maximum.'
        )

        return currently_signaling_features

    def _validate_support_intersection(self) -> None:
        if intersection := self._support_features.intersection(self._not_support_features):
            feature_names = [feature.value for feature in intersection]
            raise ValueError(f'Cannot signal both "support" and "not support" for features {feature_names}')

    def _validate_non_signaling_features(self, signaling_features: set[Feature]) -> None:
        signaled_features = self._support_features.union(self._not_support_features)

        if non_signaling_features := signaled_features.difference(signaling_features):
            feature_names = [feature.value for feature in non_signaling_features]
            self._log.warn(
                f'The following features are outside their signaling period: {feature_names}. '
                f'Signaling for them has no effect.'
            )
