#  Copyright 2024 Hathor Labs
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

from hathor.feature_activation.bit_signaling_service import BitSignalingService
from hathor.feature_activation.feature import Feature
from hathor.sysctl.sysctl import Sysctl


class FeatureActivationSysctl(Sysctl):
    def __init__(self, bit_signaling_service: BitSignalingService) -> None:
        super().__init__()
        self._bit_signaling_service = bit_signaling_service

        self.register(
            path='supported_features',
            getter=self.get_support_features,
            setter=None,
        )
        self.register(
            path='not_supported_features',
            getter=self.get_not_support_features,
            setter=None,
        )
        self.register(
            path='signaling_features',
            getter=self.get_signaling_features,
            setter=None,
        )
        self.register(
            path='add_support',
            getter=None,
            setter=self.add_feature_support,
        )
        self.register(
            path='remove_support',
            getter=None,
            setter=self.remove_feature_support,
        )

    def get_support_features(self) -> list[str]:
        """Get a list of feature names with enabled support."""
        return [feature.value for feature in self._bit_signaling_service.get_support_features()]

    def get_not_support_features(self) -> list[str]:
        """Get a list of feature names with disabled support."""
        return [feature.value for feature in self._bit_signaling_service.get_not_support_features()]

    def add_feature_support(self, *features: str) -> None:
        """Explicitly add support for a feature by enabling its signaling bit."""
        for feature in features:
            self._bit_signaling_service.add_feature_support(Feature[feature])

    def remove_feature_support(self, *features: str) -> None:
        """Explicitly remove support for a feature by disabling its signaling bit."""
        for feature in features:
            self._bit_signaling_service.remove_feature_support(Feature[feature])

    def get_signaling_features(self) -> list[str]:
        """Get a list of feature names that are currently in a signaling state."""
        features = self._bit_signaling_service.get_best_block_signaling_features().keys()
        return [feature.value for feature in features]
