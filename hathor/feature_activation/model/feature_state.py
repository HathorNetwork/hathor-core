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

from enum import Enum


class FeatureState(Enum):
    """
    Possible states a feature can be in, for each block.

    Attributes:
        DEFINED: Represents that a feature is defined. It's the first state for each feature.
        STARTED: Represents that the activation process for some feature is started.
        ACTIVE: Represents that a certain feature is activated.
        FAILED: Represents that a certain feature is not and will never be activated.
    """

    DEFINED = 'DEFINED'
    STARTED = 'STARTED'
    MUST_SIGNAL = 'MUST_SIGNAL'
    LOCKED_IN = 'LOCKED_IN'
    ACTIVE = 'ACTIVE'
    FAILED = 'FAILED'
