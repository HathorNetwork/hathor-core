#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from enum import IntEnum


class NanoRuntimeVersion(IntEnum):
    """
    The runtime version of Nano Contracts.

    It must be updated via Feature Activation and can be used to add new syscalls, for example.
    A newer version is used for all contracts as soon as the feature for that version is activated.

    V1:
      - Initial version.

    V2:
      - Added `get_settings` syscall.
    """
    V1 = 1
    V2 = 2


class BlueprintVersion(IntEnum):
    """
    The Blueprint version.

    It must be updated via Feature Activation and can be used to change the behavior of existing syscalls, for example.
    A newer version is only used for Blueprints deployed after the feature for that version is activated.
    Existing Blueprints keep the previous version's behavior.

    V1:
      - Initial version.

    V2:
      - Added `Context.blueprint_version` property.
      - Deprecated `Context.actions` property, replaced by `Context.actions_by_token`.
      - Deprecated `Context.actions_list` property, replaced by `Context.all_actions`.
      - Changed the behavior of `Context.get_single_action()` method.
      - Added `Context.get_token_single_action()` method.
    """
    V1 = 1
    V2 = 2
