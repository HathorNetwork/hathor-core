# Copyright 2023 Hathor Labs
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

from typing import Any


class DeletedKeyType:
    pass


# Placeholder to mark a key as deleted in a dict.
DeletedKey = DeletedKeyType()

# Sentinel value to differentiate where a user has provided a default value or not.
# Since _NOT_PROVIDED is a unique object, it is guaranteed not to be equal to any other value.
_NOT_PROVIDED: Any = object()
