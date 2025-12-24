#  Copyright 2025 Hathor Labs
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

from __future__ import annotations

from typing import TYPE_CHECKING, assert_never

if TYPE_CHECKING:
    from hathor.conf.settings import FeatureSetting, HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.transaction import Block

from hathor.feature_activation.feature import Feature


def _is_feature_active(
    *,
    setting: FeatureSetting,
    feature: Feature,
    block: Block,
    feature_service: FeatureService,
) -> bool:
    """Return whether a feature is active based on the setting and block."""
    # Local import to avoid circular import with hathor.conf.settings
    from hathor.conf.settings import FeatureSetting

    match setting:
        case FeatureSetting.DISABLED:
            return False
        case FeatureSetting.ENABLED:
            return True
        case FeatureSetting.FEATURE_ACTIVATION:
            return feature_service.is_feature_active(vertex=block, feature=feature)
        case _:  # pragma: no cover
            assert_never(setting)


def is_nano_active(*, settings: HathorSettings, block: Block, feature_service: FeatureService) -> bool:
    """Return whether the Nano Contracts feature is active according to the provided settings and block."""
    return _is_feature_active(
        setting=settings.ENABLE_NANO_CONTRACTS,
        feature=Feature.NANO_CONTRACTS,
        block=block,
        feature_service=feature_service,
    )


def is_fee_active(*, settings: HathorSettings, block: Block, feature_service: FeatureService) -> bool:
    """Return whether the Fee feature is active according to the provided settings and block."""
    return _is_feature_active(
        setting=settings.ENABLE_FEE_BASED_TOKENS,
        feature=Feature.FEE_TOKENS,
        block=block,
        feature_service=feature_service,
    )
