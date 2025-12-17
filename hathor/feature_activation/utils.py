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

from typing import assert_never

from hathor.conf.settings import FeatureSettingEnum, HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.transaction import Block


def is_nano_active(*, settings: HathorSettings, block: Block, feature_service: FeatureService) -> bool:
    """Return whether the Nano Contracts feature is active according to the provided settings and block."""
    match settings.ENABLE_NANO_CONTRACTS:
        case FeatureSettingEnum.DISABLED:
            return False
        case FeatureSettingEnum.ENABLED:
            return True
        case FeatureSettingEnum.FEATURE_ACTIVATION:
            return feature_service.is_feature_active(vertex=block, feature=Feature.NANO_CONTRACTS)
        case _:  # pragma: no cover
            assert_never(settings.ENABLE_NANO_CONTRACTS)


def is_fee_active(*, settings: HathorSettings, block: Block, feature_service: FeatureService) -> bool:
    """Return whether the Fee feature is active according to the provided settings and block."""
    match settings.ENABLE_FEE:
        case FeatureSettingEnum.DISABLED:
            return False
        case FeatureSettingEnum.ENABLED:
            return True
        case FeatureSettingEnum.FEATURE_ACTIVATION:
            return feature_service.is_feature_active(vertex=block, feature=Feature.FEE_TOKENS)
        case _:  # pragma: no cover
            assert_never(settings.ENABLE_FEE)
