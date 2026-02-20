# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from enum import StrEnum, auto, unique


@unique
class FeatureSetting(StrEnum):
    """Enum to configure the state of a feature."""

    # Completely disabled.
    DISABLED = auto()

    # Completely enabled since network creation.
    ENABLED = auto()

    # Enabled through Feature Activation.
    FEATURE_ACTIVATION = auto()

    def __bool__(self) -> bool:
        """
        >>> bool(FeatureSetting.DISABLED)
        False
        >>> bool(FeatureSetting.ENABLED)
        True
        >>> bool(FeatureSetting.FEATURE_ACTIVATION)
        True
        """
        return self in (FeatureSetting.ENABLED, FeatureSetting.FEATURE_ACTIVATION)
