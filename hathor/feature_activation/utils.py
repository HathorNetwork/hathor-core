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

from dataclasses import dataclass
from typing import TYPE_CHECKING, assert_never

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction.scripts.opcode import OpcodesVersion

if TYPE_CHECKING:
    from hathor.conf.settings import FeatureSetting, HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.transaction import Vertex


@dataclass(slots=True, frozen=True, kw_only=True)
class Features:
    """A dataclass holding state information about features from the Feature Activation process."""

    count_checkdatasig_op: bool
    nanocontracts: bool
    fee_tokens: bool
    opcodes_version: OpcodesVersion

    @staticmethod
    def from_vertex(*, settings: HathorSettings, feature_service: FeatureService, vertex: Vertex) -> Features:
        """Return whether the Nano Contracts feature is active according to the provided settings and vertex."""
        from hathor.conf.settings import FeatureSetting
        feature_states = feature_service.get_feature_states(vertex=vertex)
        feature_settings = {
            Feature.COUNT_CHECKDATASIG_OP: FeatureSetting.FEATURE_ACTIVATION,
            Feature.NANO_CONTRACTS: settings.ENABLE_NANO_CONTRACTS,
            Feature.FEE_TOKENS: settings.ENABLE_FEE_BASED_TOKENS,
            Feature.OPCODES_V2: settings.ENABLE_OPCODES_V2,
        }

        feature_is_active: dict[Feature, bool] = {
            feature: _is_feature_active(setting, feature_states.get(feature, FeatureState.DEFINED))
            for feature, setting in feature_settings.items()
        }

        opcodes_version = OpcodesVersion.V2 if feature_is_active[Feature.OPCODES_V2] else OpcodesVersion.V1

        return Features(
            count_checkdatasig_op=feature_is_active[Feature.COUNT_CHECKDATASIG_OP],
            nanocontracts=feature_is_active[Feature.NANO_CONTRACTS],
            fee_tokens=feature_is_active[Feature.FEE_TOKENS],
            opcodes_version=opcodes_version,
        )


def _is_feature_active(setting: FeatureSetting, state: FeatureState) -> bool:
    """Return whether a feature is active based on the setting and state."""
    from hathor.conf.settings import FeatureSetting
    match setting:
        case FeatureSetting.DISABLED:
            return False
        case FeatureSetting.ENABLED:
            return True
        case FeatureSetting.FEATURE_ACTIVATION:
            return state.is_active()
        case _:  # pragma: no cover
            assert_never(setting)
