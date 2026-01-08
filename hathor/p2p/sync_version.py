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

from enum import Enum
from functools import total_ordering


@total_ordering
class SyncVersion(Enum):
    # XXX: These values are used in the protocol to negotiate commonly supported versions, changing it will cause peers
    #      to no match different values and in turn not select a certain protocol, this can be done intentionally, for
    #      example, peers using `v2-fake` (which just uses sync-v1) will not connect to peers using `v2-alpha`, and so
    #      on.
    V2 = 'v2'

    def __str__(self):
        return f'sync-{self.value}'

    def get_priority(self) -> int:
        """Numerical indication used to sort preferred versions, higher values are preferred over lower values.

        In practice this is used to sort versions.
        """
        # XXX: these values are only used internally and in memory, there is no need to keep them consistency, for
        #      example, if we need more granularity, we can just add a 0 to all values and use the values in between,
        #      although this shouldn't really be necessary
        if self == SyncVersion.V2:
            return 20
        else:
            raise ValueError('value is either invalid for this enum or not implemented')

    # XXX: total_ordering decorator will implement the other methods: __le__, __gt__, and __ge__
    def __lt__(self, other):
        """Used to sort versions by considering the value on get_priority."""
        return self.get_priority() < other.get_priority()
