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

from enum import Enum, unique


@unique
class FeatureState(str, Enum):
    """
    Possible states a feature can be in, for each block.

    Attributes:
        DEFINED: Represents that a feature is defined. It's the first state for each feature.
        STARTED: Represents that the activation process for some feature is started.
        MUST_SIGNAL: Represents that a feature is going to be locked-in, and that miners must signal support for it.
        LOCKED_IN: Represents that a feature is going to be activated.
        ACTIVE: Represents that a certain feature is activated.
        FAILED: Represents that a certain feature is not and will never be activated.
    """

    DEFINED = 'DEFINED'
    STARTED = 'STARTED'
    MUST_SIGNAL = 'MUST_SIGNAL'
    LOCKED_IN = 'LOCKED_IN'
    ACTIVE = 'ACTIVE'
    FAILED = 'FAILED'

    def is_active(self) -> bool:
        """Return whether the state is active."""
        return self == FeatureState.ACTIVE

    @staticmethod
    def get_signaling_states() -> set['FeatureState']:
        """
        Return the states for which a feature is considered in its signaling period, that is, voting to either
        support it or not through bit signals is valid during those states.
        """
        return {FeatureState.STARTED, FeatureState.MUST_SIGNAL, FeatureState.LOCKED_IN}
