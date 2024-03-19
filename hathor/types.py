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

from typing import TypeAlias

# XXX There is a lot of refactor to be done before we can use `NewType`.
#     So, let's skip using NewType until everything is refactored.

VertexId: TypeAlias = bytes        # NewType('TxId', bytes)
Address: TypeAlias = bytes         # NewType('Address', bytes)
AddressB58: TypeAlias = str
TxOutputScript: TypeAlias = bytes  # NewType('TxOutputScript', bytes)
Timestamp: TypeAlias = int         # NewType('Timestamp', int)
TokenUid: TypeAlias = VertexId     # NewType('TokenUid', VertexId)
Amount: TypeAlias = int            # NewType('Amount', int)
