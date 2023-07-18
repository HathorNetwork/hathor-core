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
class Feature(Enum):
    """
    An enum containing all features that participate in the feature activation process, past or future, activated
    or not, for all networks. Features should NOT be removed from this enum, to preserve history. Their values
    should NOT be changed either, as configuration uses them for setting feature activation criteria.
    """

    NOP_FEATURE_1 = 'NOP_FEATURE_1'
    NOP_FEATURE_2 = 'NOP_FEATURE_2'
    NOP_FEATURE_3 = 'NOP_FEATURE_3'
