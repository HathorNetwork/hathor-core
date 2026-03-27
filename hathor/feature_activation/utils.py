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

from hathor.daa import DAAVersion
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.nanocontracts.nano_runtime_version import NanoRuntimeVersion
from hathor.transaction.scripts.opcode import OpcodesVersion

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.transaction import Block, Vertex
    from hathorlib.conf.settings import FeatureSetting


@dataclass(slots=True, frozen=True, kw_only=True)
class Features:
    """A dataclass holding state information about features from the Feature Activation process."""

    count_checkdatasig_op: bool
    nanocontracts: bool
    fee_tokens: bool
    opcodes_version: OpcodesVersion
    nano_runtime_version: NanoRuntimeVersion
    daa_version: DAAVersion

    @staticmethod
    def from_vertex(*, settings: HathorSettings, feature_service: FeatureService, vertex: Vertex) -> Features:
        """Return information about each feature according to the state in the provided vertex."""
        from hathorlib.conf.settings import FeatureSetting
        feature_states = feature_service.get_feature_states(vertex=vertex)
        feature_settings = {
            Feature.COUNT_CHECKDATASIG_OP: FeatureSetting.FEATURE_ACTIVATION,
            Feature.NANO_CONTRACTS: settings.ENABLE_NANO_CONTRACTS,
            Feature.FEE_TOKENS: settings.ENABLE_FEE_BASED_TOKENS,
            Feature.OPCODES_V2: settings.ENABLE_OPCODES_V2,
            Feature.NANO_RUNTIME_V2: settings.ENABLE_NANO_RUNTIME_V2,
            Feature.REDUCE_DAA_TARGET: FeatureSetting.FEATURE_ACTIVATION,
        }

        feature_is_active: dict[Feature, bool] = {
            feature: _is_feature_active(setting, feature_states.get(feature, FeatureState.DEFINED))
            for feature, setting in feature_settings.items()
        }

        opcodes_version = OpcodesVersion.V2 if feature_is_active[Feature.OPCODES_V2] else OpcodesVersion.V1
        nano_runtime_version = (
            NanoRuntimeVersion.V2 if feature_is_active[Feature.NANO_RUNTIME_V2] else NanoRuntimeVersion.V1
        )
        daa_version = (
            DAAVersion.V2 if feature_is_active[Feature.REDUCE_DAA_TARGET] else DAAVersion.V1
        )

        return Features(
            count_checkdatasig_op=feature_is_active[Feature.COUNT_CHECKDATASIG_OP],
            nanocontracts=feature_is_active[Feature.NANO_CONTRACTS],
            fee_tokens=feature_is_active[Feature.FEE_TOKENS],
            opcodes_version=opcodes_version,
            nano_runtime_version=nano_runtime_version,
            daa_version=daa_version,
        )

    @staticmethod
    def for_mempool(*, settings: HathorSettings, feature_service: FeatureService, best_block: Block) -> Features:
        """
        Used for mempool verification.

        Features can either be more restrictive (for example, `count_checkdatasig_op`) or more permissive
        (for example, `nanocontracts`) in relation to vertex verification. When a feature doesn't affect
        verification, such as changes to the Nano runtime only (`nano_runtime_version`), it is indifferent.

        Returns information about each feature where permissive features come from the state in the provided
        block, and restrictive features are always enabled. This means restrictive features are applied in
        mempool verification regardless of features states in the current best block.
        """
        features = Features.from_vertex(settings=settings, feature_service=feature_service, vertex=best_block)
        return Features(
            # Restrictive features (hardcoded as enabled):
            count_checkdatasig_op=True,
            opcodes_version=OpcodesVersion.V2,
            # Permissive features (come from the block state):
            nanocontracts=features.nanocontracts,
            fee_tokens=features.fee_tokens,
            # Indifferent features (come from the block state):
            nano_runtime_version=features.nano_runtime_version,
            daa_version=features.daa_version,
        )

    @staticmethod
    def all_enabled() -> Features:
        """
        Used mostly for APIs and tests, it disregards the actual state of the blockchain
        and hardcodes all features as enabled.

        - For restrictive features, this means they're restricted on APIs just like in the mempool.
        - For permissive features, they're allowed on APIs, which is fine since they may be blocked
          during verification anyway.
        - For indifferent features, it doesn't matter.

        Read the `Features.for_mempool` docstring for more details on these types of features.
        """
        return Features(
            count_checkdatasig_op=True,
            nanocontracts=True,
            fee_tokens=True,
            opcodes_version=OpcodesVersion.V2,
            nano_runtime_version=NanoRuntimeVersion.V2,
            daa_version=DAAVersion.V2,
        )


def _is_feature_active(setting: FeatureSetting, state: FeatureState) -> bool:
    """Return whether a feature is active based on the setting and state."""
    from hathorlib.conf.settings import FeatureSetting
    match setting:
        case FeatureSetting.DISABLED:
            return False
        case FeatureSetting.ENABLED:
            return True
        case FeatureSetting.FEATURE_ACTIVATION:
            return state.is_active()
        case _:  # pragma: no cover
            assert_never(setting)
