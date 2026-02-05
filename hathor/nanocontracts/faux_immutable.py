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

# Re-export from hathorlib for backward compatibility
from hathorlib.nanocontracts.faux_immutable import (  # noqa: F401
    ALLOW_DUNDER_ATTR,
    ALLOW_INHERITANCE_ATTR,
    SKIP_VALIDATION_ATTR,
    FauxImmutable,
    FauxImmutableMeta,
    __set_faux_immutable__,
    create_with_shell,
)
