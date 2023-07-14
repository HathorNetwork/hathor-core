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

        self._validate_support_intersection()

    def start(self) -> None:
        best_block = self._tx_storage.get_best_block()

        self._warn_non_signaling_features(best_block)
        self._log_feature_signals(best_block)

    def generate_signal_bits(self, *, block: Block, log: bool = False) -> int:
        """
        Generate signal bits considering a given block. The block is used to determine which features are currently in
        a signaling period.

        Args:
            block: the block that is used to determine signaling features.
            log: whether to log the signal for each feature.

        Returns: a number that represents the signal bits in binary.
        """
        signaling_features = self._get_signaling_features(block)
        signal_bits = 0

        for feature, criteria in signaling_features.items():
            default_enable_bit = criteria.signal_support_by_default
            support = feature in self._support_features
            not_support = feature in self._not_support_features
            enable_bit = (default_enable_bit or support) and not not_support

            if log:
                self._log_signal_bits(feature, enable_bit, support, not_support)

            signal_bits |= int(enable_bit) << criteria.bit

        return signal_bits

    def _log_signal_bits(self, feature: Feature, enable_bit: bool, support: bool, not_support: bool) -> None:
        """Generate info log for a feature's signal."""
        action = 'Enabling' if enable_bit else 'Disabling'
        reason = 'using default feature signal'

        if support:
            reason = 'user signaled support'

        if not_support:
            reason = 'user signaled not support'

        self._log.info(f'{action} support signal for feature "{feature.value}". Reason: {reason}.')

    def _get_signaling_features(self, block: Block) -> dict[Feature, Criteria]:
        """Given a specific block, return all features that are in a signaling state for that block."""
        feature_descriptions = self._feature_service.get_bits_description(block=block)
        signaling_features = {
            feature: description.criteria
            for feature, description in feature_descriptions.items()
            if description.state in FeatureState.get_signaling_states()
        }

        assert len(signaling_features) <= self._feature_settings.max_signal_bits, (
            'Invalid state. Signaling more features than the allowed maximum.'
        )

        return signaling_features

    def _validate_support_intersection(self) -> None:
        """Validate that the provided support and not-support arguments do not conflict."""
        if intersection := self._support_features.intersection(self._not_support_features):
            feature_names = [feature.value for feature in intersection]
            raise ValueError(f'Cannot signal both "support" and "not support" for features {feature_names}')

    def _warn_non_signaling_features(self, best_block: Block) -> None:
        """Generate a warning log if any signaled features are currently not in a signaling state."""
        currently_signaling_features = self._get_signaling_features(best_block)
        signaled_features = self._support_features.union(self._not_support_features)

        if non_signaling_features := signaled_features.difference(currently_signaling_features):
            feature_names = {feature.value for feature in non_signaling_features}
            self._log.warn(
                'Considering the current best block, there are signaled features outside their signaling period. '
                'Therefore, signaling for them has no effect. Make sure you are signaling for the desired features.',
                best_block_hash=best_block.hash_hex,
                best_block_height=best_block.get_height(),
                non_signaling_features=feature_names
            )

    def _log_feature_signals(self, best_block: Block) -> None:
        """Generate info logs for each feature's current signal."""
        signal_bits = self.generate_signal_bits(block=best_block, log=True)

        self._log.debug(f'Configured signal bits: {bin(signal_bits)[2:]}')
