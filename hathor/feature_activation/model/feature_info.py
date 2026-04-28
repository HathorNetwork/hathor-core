# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import NamedTuple

from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState


class FeatureInfo(NamedTuple):
    """Represents all information related to one feature, that is, its criteria and state."""
    criteria: Criteria
    state: FeatureState
